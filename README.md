# 项目名称

BIF-Core-SDK-C是C语言版BIF-Core SDK，通过API调用的方式提供了星火链网-底层区块链平台相关接口。

## 功能特性

BIF-Core-SDK-C通过API调用的方式提供了星火链网-底层区块链平台公私钥对生成、星火链网-底层区块链平台私钥签名公钥验签、账号服务、区块服务、交易服务等接口，同时还提供了接口使用示例说明，开发者可以调用该SDK方便快捷的生成星火链网主链的快速接入。

## 快速开始

### SDK库编译与安装

首先编译sdk的动态和静态库并安装到对应目录

```c
## 1.拉取BIF-Core-SDK-C源码
git clone https://github.com/caict-4iot-dev/BIF-Core-SDK.git
## 2.编译与安装
1) cd BIF-Core-SDK-C
2) mkdir build && cd build
3) cmake ..
4) make && make install 
##通过以上命令最后将编译的sdk动态库,静态库及对应头文件安装到目录：
./build/lib为库目录
./build/include 头文件目录
```

### example示例编译

```c
##在SDK源码目录的examplem子目录下执行如下命令
1）mkdir build && cd build
2）cmake ..
3）make或者make 指定示例文件名字
make后生成对应示例可执行文件，其中单独的make是编译所有示例，如果make后面跟着对应文件名的方式代表只编译指定的示例。

备注：example中编译链接默认是链接的sdk动态库（因为动态库，静态库同时存在优先链接动态库），如果用要有静态库编译example可执行程序，需要将静态库指定到另外单独的目录，并且除了正常所需头文件要将sdk静态库依赖的3rd第三方头文件和库目录同时指定编译（因为静态库的特殊性，实质上是打包编译阶段就要集成编译进去，所以除了业务正常的头文件还需要将依赖的头文件及库同时指定一起编译）
```

#### 引用

在要使用sdk的源文件里使用引用sdk库，步骤如下：

```c
一.动态库使用方式
    1.由上述编译sdk库所生成的根目录的build目录下lib库和include指定到自定义所需目录
    2.在自己工程对应源文件按照example所示包含对应接口头文件，并初始化调用对应接口
    3.在自己makefile或者CMakelist.txt中添加对应库名及头文件，库目录的指定
    4.编译工程即可
二.静态库使用方式
    1.由上述编译sdk库所生成的lib静态库和sdk源码根目录下include指定到自定义所需目录
    2.在自己工程对应的源文件中按照example所示包含对应接口头文件，并初始化调用对应接口
    3.在自己makefile或者CMakelist.txt中添加对应库名及头文件，库目录的指定
    4.编译工程即可
```

#### 应用demo

c sdk应用示例，请参考[ BIF-Core-SDK-C\example](example)

## 使用指南
- BIF-Core-SDK-C目录：BIF-Core-SDK-C的整体项目开源代码  
- example目录：BIF-Core-SDK-C演示example 

详见[BIF-Core-SDK-C](./docs/SDK_design_for_C.md)

## 文档

- [LICENSE](./LICENSE)
- [BIF-Core-SDK-C](https://bif-core-dev-doc.readthedocs.io/zh_CN/v1.0.0/index.html)

## 如何贡献

欢迎参与“星火·链网”主链服务的生态建设：

1. 如项目对您有帮助，欢迎点亮我们的小星星(点击项目上方Star按钮)。

2. 欢迎提交代码(Pull requests)。

3. 提问和提交BUG。

4. 邮件反馈：zhangzhiliang@caict.ac.cn

   我们将尽快给予回复。
   
## 关于作者

中国信通院秉持开源开放的理念，将星火“BID-Core-SDK-C”面向社区和公众完全开源，助力全行业伙伴提升数据价值流通的效率，实现数据价值转化。

## 许可证

[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0)

版权所有 2023 中国信息通信研究院工业互联网与物联网研究所
