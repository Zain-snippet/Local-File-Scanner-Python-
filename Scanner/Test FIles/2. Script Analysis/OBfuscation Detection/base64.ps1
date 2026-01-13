$e = "V3JpdGUtT3V0cHV0ICJIZWxsbyBGcm9tIE9iZnVzY2F0ZWQgU2NyaXB0Ig=="
$decoded = [System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String($e)
)
Invoke-Expression $decoded
