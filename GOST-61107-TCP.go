package GOST_61107_TCP

//
//

import (
  "time"
  "errors"
  "net"
  "fmt"
  _ "strings"
  _ "bytes"
  _ "encoding/hex"
)

const MAX_REPLY_LEN int = 4096

const SOH byte = 0x01
const STX byte = 0x02
const ETX byte = 0x03
const ACK byte = 0x06
const NACK byte = 0x15

type Dev struct {
  conn net.Conn
  Connected bool
  ip string
  port string
  timeout time.Duration
  stop_ch chan string
  Debug bool
  ReturnTrap bool
  Bytes_in uint64
  Bytes_out uint64
  Bytes_since time.Time
  Mode string
  Delay time.Duration
}

type Message struct {
  Type byte // 1 - query, 2 - data, 3 - empty data?, 6 - ack, 0x16 nack
  Head string
  Body string
}

func Init(ip string, port string, mode string, timeout time.Duration, stop_ch chan string) (*Dev) {

  if mode != "0" && mode != "1" {
    panic("Unknown mode passed")
  }

  dev :=new(Dev)
  dev.Connected=false
  dev.ip=ip
  dev.port=port
  dev.timeout=timeout
  dev.stop_ch=stop_ch
  dev.Debug=false
  dev.ReturnTrap=false
  dev.Bytes_in=0
  dev.Bytes_out=0
  dev.Bytes_since=time.Now()
  dev.Mode=mode
  dev.Delay=300*time.Millisecond
  return dev
}

func (dev *Dev) Close() {
  if(dev.conn != nil) {
    dev.SendBytes([]byte("\x01\x42\x30\x03\x75"))
    if(dev.Debug) { fmt.Println("Closing connection") }
    dev.conn.Close()
    dev.Connected=false
    dev.conn=nil
  }
  return
}

func (dev *Dev) readByte() (byte, error) {
  read_buff := make([]byte, 1)

  err := dev.conn.SetDeadline(time.Now().Add(dev.timeout))
  if(err != nil) { dev.Close(); return 0,err }

  read, err := dev.conn.Read(read_buff)
  if(err != nil) { dev.Close(); return 0,err }

  dev.Bytes_in += uint64(read)

  if(read == 0) { dev.Close(); return 0,errors.New("Short read") }
  if(read != 1) { dev.Close(); return 0,errors.New(fmt.Sprintf("Too much read: %d, expected: %d", read, 1)) }

  select {
    case cmd := <-dev.stop_ch:
      if(cmd == "stop") {
        dev.Close();
        return 0,errors.New("exit signalled")
      }
    default:
      //do nothing
  }
  return read_buff[0], nil
}

func calcBcc(bytes []byte) (byte) {
  lrc := byte(0)
  for _, b := range bytes {
    lrc = (lrc + b) & 0x7F
  }
  return lrc
}

func (dev *Dev) ReadMessage() (*Message, error) {
  read_buff := make([]byte, 1024)
  buff := make([]byte, 0)

  ret := &Message{}

  timer := time.NewTimer(2*time.Second)
  defer func() {
    if !timer.Stop() {
      <-timer.C
    }
  }()

  for ;; {
    err := dev.conn.SetDeadline(time.Now().Add(dev.timeout))
    if(err != nil) { dev.Close(); return nil, err }

    read, err := dev.conn.Read(read_buff)
    if(err != nil) {
      dev.Close(); return nil,err
    }

    dev.Bytes_in += uint64(read)
    if(read == 0) { dev.Close(); return nil,errors.New("Short read") }

    if dev.Debug {
      fmt.Print("> ")
      DumpBytes(read_buff[:read])
    }

    if read > len(read_buff) {
      return nil,errors.New("Input buffer overflow")
    }

    if (len(buff) + read) > MAX_REPLY_LEN {
      return nil,errors.New("Reply size exceeded limit")
    }

    buff = append(buff, read_buff[:read]...)

    if buff[0] == ACK || buff[0] == NACK {
      //ACK or NACK, should be no more data in the buffer
      if len(buff) > 1 {
        dev.Close();
        return nil,errors.New("Protocol error, extra data after ACK/NACK")
      }
      ret.Type = buff[0]
      return ret, nil
    } else if buff[0] == ETX && len(buff) > 1 {
      if len(buff) != 2 {
        dev.Close();
        return nil,errors.New("Protocol error, extra data after empty ETX")
      }
      if buff[1] != 0x03 { // bcc of ETX is ETX
        dev.Close();
        return nil,errors.New("Control summ check failed")
      }
      ret.Type = STX
      return ret, nil
    }
    if buff[0] != SOH && buff[0] != STX {
      dev.Close();
      return nil,errors.New("Protocol error, unknown message type")
    }

    bl := len(buff)
    ret.Type = buff[0]

    if bl >= 3 && ret.Type == STX {
      // STX
      if buff[bl - 2] == ETX {
        // complete message, check and return
        if bl == 3 {
          //empty message with STX is unnacceptable (perhaps?)
          dev.Close();
          return nil,errors.New("Protocol error, empty STX")
        }
        bcc := calcBcc(buff[1:bl-1])
        if bcc != buff[bl-1] {
          return nil,errors.New("Control summ check failed")
        }
        ret.Body = string(buff[1:bl - 2])
        return ret, nil
      }
    } else if bl >= 5 && ret.Type == SOH {
      //SOH, have header and data with STX_ETX or no data with ETX only
      if buff[bl - 2] == ETX {
        // complete message, check and return
        bcc := calcBcc(buff[1:bl-1])
        if bcc != buff[bl-1] {
          return nil,errors.New("Control summ check failed")
        }
        ret.Head = string(buff[1:3])
        if bl > 5 && buff[3] != STX {
          //no STX after header in long mesage
          dev.Close();
          return nil,errors.New("Protocol error, no STX after SOH header")
        }
        if buff[3] == STX {
          ret.Body = string(buff[4:bl-2])
        } //else empty body

        return ret, nil
      }
    }

    select {
      case <-timer.C:
        // tired of waitin for full string
        return nil,errors.New("Tired of wating")

      case cmd := <-dev.stop_ch:
        if(cmd == "stop") {
          dev.Close();
          return nil,errors.New("exit signalled")
        }

      default:
        //do nothing
    }
  }
}

func (dev *Dev) ReadCRLF() (string, error) {
  read_buff := make([]byte, 1024)
  buff := make([]byte, 0)

  timer := time.NewTimer(2*time.Second)
  defer func() {
    if !timer.Stop() {
      <-timer.C
    }
  }()

  for ;; {
    err := dev.conn.SetDeadline(time.Now().Add(dev.timeout))
    if(err != nil) { dev.Close(); return "",err }

    read, err := dev.conn.Read(read_buff)
    if(err != nil) {
      dev.Close(); return "",err
    }

    dev.Bytes_in += uint64(read)
    if(read == 0) { dev.Close(); return "",errors.New("Short read") }

    if dev.Debug {
      fmt.Print("> ")
      DumpBytes(read_buff[:read])
    }

    if read > len(read_buff) {
      return "",errors.New("Input buffer overflow")
    }

    if (len(buff) + read) > MAX_REPLY_LEN {
      return "",errors.New("Reply size exceeded limit")
    }

    buff = append(buff, read_buff[:read]...)

    if len(buff) >= 2 && string(buff[len(buff)-2:]) == "\r\n" {
      return string(buff[:len(buff)-2]), nil
    }

    select {
      case <-timer.C:
        // tired of waitin for full string
        return "",errors.New("Tired of wating")

      case cmd := <-dev.stop_ch:
        if(cmd == "stop") {
          dev.Close();
          return "",errors.New("exit signalled")
        }

      default:
        //do nothing
    }
  }
}

func (dev *Dev) SendBytes(bytes []byte) (error) {
  err := dev.conn.SetDeadline(time.Now().Add(dev.timeout))
  if(err != nil) { dev.Close(); return err }

  if dev.Debug {
    fmt.Print("< ")
    DumpBytes(bytes)
  }

  sent, err := dev.conn.Write(bytes)
  if(err != nil) { dev.Close(); return err }

  dev.Bytes_out += uint64(sent)
  if(sent != len(bytes)) { dev.Close(); return errors.New("short write") }

  select {
    case cmd := <-dev.stop_ch:
      if(cmd == "stop") {
        dev.Close();
        return errors.New("exit signalled")
      }
    default:
      //do nothing
  }

  return nil
}

func (dev *Dev) Connect() (error) {
  if(dev.Connected) { return errors.New("already connected") }
  var err error
  dev.conn, err = net.DialTimeout("tcp", dev.ip+":"+dev.port, dev.timeout)
  if(err != nil) { return err }
  dev.Connected=true

  //send start request
  start_req := []byte("/?!\r\n")
  if dev.Debug {
    fmt.Println("  Sending start request")
  }
  err = dev.SendBytes(start_req)
  if(err != nil) { return err }

  //get ident reply
  ident, err := dev.ReadCRLF()
  if(err != nil) { return err }

  if dev.Debug {
    fmt.Println("  ident: "+ident)
  }

  if ident[:1] != "/" {
    dev.Close()
    return errors.New("No / in ident reply")
  }

  if len(ident) < 6 {
    dev.Close()
    return errors.New("Too short ident reply")
  }

  // fith char is baud rate of device, leave it as is
  baud_rate_char := ident[4:5]

  // if fourth char is small letter, device minimum reaction time is 20ms, otherwise 0 200ms

  react_char := []rune(ident)[3]
  if react_char >= 'a' && react_char <= 'z' {
    dev.Delay = 30*time.Millisecond
  } else {
    dev.Delay = 300*time.Millisecond
  }

  time.Sleep(dev.Delay)

  mode_select := []byte("\x06"+"0"+baud_rate_char+dev.Mode+"\r\n")

  if dev.Debug {
    fmt.Println("  Sending Acknowledge")
  }

  err = dev.SendBytes(mode_select)
  if(err != nil) { return err }


  // you HAVE to read reply after calling Connect

  return nil
}

func DumpBytes(bytes []byte) {
  fmt.Printf("\t% X\n", bytes)
  fmt.Print("\n")
}


func (dev *Dev) Query(head, body string) (*Message, error) {
  if len(head) != 2 {
    dev.Close();
    return nil,errors.New("head length != 2")
  }

  if dev.Debug {
    fmt.Println("  Sending query: "+head+" "+body)
  }

  send := make([]byte, 0)
  send = append(send, SOH)
  send = append(send, []byte(head)...)

  if len(body) > 0 {
    send = append(send, STX)
    send = append(send, []byte(body)...)
  }

  send = append(send, ETX)

  bcc := calcBcc(send[1:])
  send = append(send, bcc)

  time.Sleep(dev.Delay)

  err := dev.SendBytes(send)
  if err != nil {
    return nil, err
  }

  time.Sleep(dev.Delay)

  ret, err := dev.ReadMessage()
  if err != nil {
    return nil, err
  }
  return ret, nil

}
