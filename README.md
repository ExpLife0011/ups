# ups-通过udp协议实现的数据可靠传输库，分为c++和java两个版本

#### 项目介绍
通过udp模拟tcp进行可靠数据传输，可以用通过udp协议进行文件传送。本开发库可以应用于一些特殊的应用场景，比如在尝试进行net穿透的时候，udp显然比tcp有更大的优势，但是udp本身又不能像tcp协议能够保证数据的可靠传输，这种情况就可以尝试使用我们的ups传输库了。

#### 软件架构
      本工程的实现原理是通过udp模拟tcp的ack确认重传机制来保证数据传输的可靠性，通过序号保证数据的时序性，同时模拟“tcp滑动窗口”防止数据

#### 安装教程

1. xxxx
2. xxxx
3. xxxx

#### 使用说明

1. xxxx
2. xxxx
3. xxxx

#### 参与贡献

1. Fork 本项目
2. 新建 Feat_xxx 分支
3. 提交代码
4. 新建 Pull Request


#### 码云特技

1. 使用 Readme\_XXX.md 来支持不同的语言，例如 Readme\_en.md, Readme\_zh.md
2. 码云官方博客 [blog.gitee.com](https://blog.gitee.com)
3. 你可以 [https://gitee.com/explore](https://gitee.com/explore) 这个地址来了解码云上的优秀开源项目
4. [GVP](https://gitee.com/gvp) 全称是码云最有价值开源项目，是码云综合评定出的优秀开源项目
5. 码云官方提供的使用手册 [http://git.mydoc.io/](http://git.mydoc.io/)
6. 码云封面人物是一档用来展示码云会员风采的栏目 [https://gitee.com/gitee-stars/](https://gitee.com/gitee-stars/)