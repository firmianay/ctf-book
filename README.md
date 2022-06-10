# CTF竞赛权威指南(Pwn篇) 相关资源

[关于本书](https://github.com/firmianay/CTF-All-In-One)

[京东购买](https://item.jd.com/13041828.html) [当当购买](http://product.dangdang.com/29166115.html)

读者交流QQ群：808542982、217863340

微信群请加我微信，备注“加群”。欢迎关注公众号：

<table><tr>
<td><img src=./gzh.jpg width="100"></td>
<td><img src=./wechat.jpg width="100"></td>
</tr></table>

**图书编写耗时费力，倾注了作者大量的心力，打击盗版，维护正版！**

## 勘误

感谢广大热心读者的关注，如发现本书内容有误，请以 issue 的方式告知我们～

- 第 1 次印刷（2020-12）：
  - P48：文字倒数第二段，改为 `第二行是普通文件（-），第三行是链接文件（l）`。 -- @七星
  - P171：文字倒数第四行和倒数第一行的覆盖地址，改为 `/x28/xcd/xff/xff`。 -- @LTSHFWJT
  - P172：第三个代码块的第一行 print 后面的 `AA%15$nA` 改为 `A%15$hhn`。 -- @LTSHFWJT
- 第 2 次印刷（2021-01）（从本次印刷开始有个彩蛋，欢迎寻找）：
  - P142：第一个代码块 shellcode 一行改为 `(*(void(*)())shellcode)();`。 -- @winter
  - P215：文字第二段倒数第二行的参数，改为 `reloc_index`。 -- @Return
  - P228：PREV_INUSE 部分，改为 `当它为 1 时，表示上一个 chunk 处于使用状态，否则表示上一个 chunk 处于释放状态`。 -- @These-us
  - P230：unsorted bin 部分，`unsroted bin 中的 chunk 大小可能是不同的` 中的 `unsroted` 改为 `unsorted`。 -- @Y7n05h
  - P234：代码部分，`如果下一个 chunk 处于使用状态则执行向前合并操作` 中的 `使用状态` 改为 `空闲状态`。 -- @Y7n05h
  - P410：文字第二段第一行，改为 `栈是从高地址向低地址增长的`。 -- @unr4v31
- 第 3 次印刷（2021-08）：
  - P229：fast bin部分第三行 `PRV_INUSE` 改为 `PREV_INUSE`。 -- @李寻欢
- 第 4 次印刷（2022-01）：

## 关注我们

[VulnTotal安全团队](https://github.com/VulnTotal-Team)的翻译组，负责从国外优秀媒体翻译 安全/计算机 相关的技术、资讯、论文等内容。欢迎更多的志愿者[关注或加入我们](https://github.com/VulnTotal-Team/TranslateProject)。
