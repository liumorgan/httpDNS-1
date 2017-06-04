$host = $_GET["dn"];
if ($host == NULL)
    $host = $_GET["host"];
if ($host == NULL)
    return;
$ip = gethostbyname("$host");
if ($ip == $host)
{
    header("Content-type: text/html; charset=utf-8");
    echo '<html><head><title>HTTP DNS Server</title></head><body>查询域名失败<br/><br/>By: 萌萌萌得不要不要哒</body></html>';
}
else
    echo "$ip"; 
