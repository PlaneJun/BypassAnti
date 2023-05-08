# Information

`Loader`为自写的shellcode，用于执行真正代码前对代码进行解密和恢复。

1、计算所需的新节区大小，然后为PE文件新增一个节区(默认名为'.ba')，然后

2、将代码段的首四个字节作为key进行加密所有的代码段数据，加密结束后将key使用xor运算后保存到Loader中，并将xor_key写出到`c:\d3d9.dll`(默认选项).

> 这个操作是为了过掉杀软的沙箱扫描。key与程序分离后，程序就在沙箱无法正常运行，从而绕过沙箱。

3、写入Loader，修改入口点为Loader。

程序后Loader会读取`c:\d3d9.dll`中的内容与加密key进行xor解密，然后开始解密代码段，当所有解密完成时会跳转到原始入口进行执行。

# OS

支持Window、Linux。

# Usage

```
Usage: BypassAnti
        -f              (required) filename
        -k              (optional) key filename,default 'c:\d3d9.dll'
        -s              (optional) new section name,default '.ba'
        [-d]    (optional) automatically delete key file after running
```

# Examples

对文件进行加密

```
BypassAnti -f C:\Users\PlaneJun\Desktop\Qbot
```

加密后会在目录下生成一个`d3d9.dll`，存放xor秘钥。使用卡巴扫描加密前的程序。

![image-20230506182214310](imgs\image-20230506182214310.png)

加密后的程序：

![image-20230506182232419](imgs\image-20230506182232419.png)

如果想自定义节区名字，可以使用`-s`指定。

```
BypassAnti -f C:\Users\PlaneJun\Desktop\Qbot -s .my
```

如果想自定义秘钥文件路径，可以使用`-k`指定。

```
BypassAnti -f C:\Users\PlaneJun\Desktop\Qbot -k C:\Users\PlaneJun\Desktop\1.dll
```

如果想让程序运行后自动删除秘钥文件，可以使用`-d`.

```
BypassAnti -f C:\Users\PlaneJun\Desktop\Qbot -d
```

# Compile

## Loader

Loader需要用Visual Studio进行编译。其中配置需要进行如下调整：

1、关闭优化。

- 项目属性-高级-全程序优化。`否`
- 项目属性-C/C++-优化-优化。`否`
- 项目属性-C/C++-优化-启用内部函数。`否`
- 项目属性-C/C++-优化-全程序优化。`否`

2、关闭cookies检查。

- 项目属性-C/C++-代码生成-安全检查。`禁用安全检查`

3、管理配置调节至Release。

> x64编译loader需要添加asm依赖项。方式：右键项目-生成依赖项-生成自定义，勾选masm即可。x86编译则需要取消该依赖项。

---

编译完成后，使用ida打开loader并加载调试符号，截取对应shellcode。

![image-20230508103137165](imgs\image-20230508103137165.png)

将红框区域代码全部选中，然后Shift+E，将生成的字节码复制粘贴到BypassAnti中。

![image-20230508103305128](imgs\image-20230508103305128.png)

其中前四个字节需要手动填充，内容为Loader函数相对于首字节的位置+5。

![image-20230508103425268](imgs\image-20230508103425268.png)

## BypassAnti

### Windows

VS修改项目语法为C++20以上版本。

![image-20230508103541328](imgs\image-20230508103541328.png)

然后直接编译即可。

### Linux

g++需要添加编译命令`-std=c++20`，然后编译即可。

```
g++ -g *.cpp -o /home/planejun/桌面/BypassAnti/main -std=c++20
```

# Support

| File Type     | x86  | x64  |
| ------------- | ---- | ---- |
| PE executable | ✔️    | ✔️    |

# TODO

经过测试，加密后部分程序可以达到免杀，但如果程序的资源区存在一些恶意数据，且已经被作为特征上传的EDR，这样依旧会被终端报黑。