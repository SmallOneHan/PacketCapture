# PacketsCapture
WireShark是一款强大的网络协议数据包分析工具，底层基于libpcap、winpcap实现。本项目实现基于libcap的简单数据包抓取功能，供学习参考。

## 安装Libcap
解压进入源代码目录
```
./config
make
sudo make install
```
将生成的so文件复制到 /usr/lib 目录
```
sudo cp libpcap.so.1.7.4 /usr/lib/libpcap.so.1
```

## 编译
```make```
生成可执行文件PacketsCapture

## 执行
```sudo ./PacketsCapture```


使用方法即源码结构参考 introduction.doc Libpcap-Libnet.pdf
