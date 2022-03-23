package backendtool

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"
)

var loggerStd = newStd()

type logger struct {
	appName string
	terminal bool
	outFile bool
	outFileWriter *os.File
	outService bool // 日志输出到服务
	outServiceIp string
	outServicePort int
	outServiceConn  *net.UDPConn
	outServiceLevel []int
}

func newStd() *logger {
	return &logger{
		terminal: true,
		outFile: false,
		outService: false,
		outServiceLevel: []int{3, 4, 5},
	}
}

func SetLogFile(name string) {
	loggerStd.outFile = true
	loggerStd.appName = name
	loggerStd.outFileWriter, _ = os.OpenFile( name+time.Now().Format("-20060102")+".log",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
}


func SetOutServiceWarn2Panic() {
	loggerStd.outServiceLevel = []int{3, 4, 5}
}

func SetOutServiceInfo2Panic() {
	loggerStd.outServiceLevel = []int{1, 2, 3, 4, 5}
}

func DisableTerminal() {
	loggerStd.terminal = false
}

type Level int

var LevelMap = map[Level]string {
	1 : "Info  ",
	2 : "Debug ",
	3 : "Warn  ",
	4 : "Error ",
	5 : "Panic ",
}

func (l *logger) Log(level Level, args string, times int) {
	var buffer bytes.Buffer
	buffer.WriteString(time.Now().Format("2006-01-02 15:04:05 |"))
	buffer.WriteString(LevelMap[level])
	_, file, line, _ := runtime.Caller(times)
	buffer.WriteString("|")
	buffer.WriteString(file)
	buffer.WriteString(":")
	buffer.WriteString(strconv.Itoa(line))
	buffer.WriteString(" : ")
	buffer.WriteString(args)
	buffer.WriteString("\n")
	out := buffer.Bytes()
	if l.terminal {
		_,_ = buffer.WriteTo(os.Stdout)
	}

	go func(out []byte) {
		if l.outFile {
			_,_ = l.outFileWriter.Write(out)
		}

		if l.outService {
			for _, v := range l.outServiceLevel {
				if Level(v) == level {
					out = append([]byte("1"+l.appName+"|"), out...)
					_,_ = l.outServiceConn.Write(out)
				}
			}
		}
	}(out)
}

func Info(args ...interface{}) {
	loggerStd.Log(1, fmt.Sprint(args...), 2)
}

func HttpInfo(args ...interface{}) {
	loggerStd.Log(1, fmt.Sprint(args...), 1)
}

func Infof(format string, args ...interface{}) {
	loggerStd.Log(1, fmt.Sprintf(format, args...), 2)
}

func InfoTimes(times int, args ...interface{}) {
	loggerStd.Log(1, fmt.Sprint(args...), times)
}

func Debug(args ...interface{}) {
	loggerStd.Log(2, fmt.Sprint(args...), 2)
}

func Debugf(format string, args ...interface{}) {
	loggerStd.Log(2, fmt.Sprintf(format, args...), 2)
}

func DebugTimes(times int, args ...interface{}) {
	loggerStd.Log(2, fmt.Sprint(args...), times)
}

func Warn(args ...interface{}) {
	loggerStd.Log(3, fmt.Sprint(args...), 2)
}

func Warnf(format string, args ...interface{}) {
	loggerStd.Log(3, fmt.Sprintf(format, args...), 2)
}

func WarnTimes(times int, args ...interface{}) {
	loggerStd.Log(3, fmt.Sprint(args...), times)
}

func Error(args ...interface{}) {
	loggerStd.Log(4, fmt.Sprint(args...), 2)
}

func Errorf(format string, args ...interface{}) {
	loggerStd.Log(4, fmt.Sprintf(format, args...), 2)
}

func ErrorTimes(times int, args ...interface{}) {
	loggerStd.Log(4, fmt.Sprint(args...), times)
}

func Panic(args ...interface{}){
	loggerStd.Log(5, fmt.Sprint(args...), 2)
	panic(args)
}

func InitLogger(){
	// 日志设置
	if ConfArg.LogCentre != nil {
		SetOutServiceInfo2Panic()
	}
}

