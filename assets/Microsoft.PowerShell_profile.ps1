function ll(){
    Write-Host "Remember you are not on linux ;)"
    Get-ChildItem -Hidden
}

#Git Ignore
Function New-GitIgnore {
  param(
    [Parameter(Mandatory=$true)]
    [string[]]$list
  )
  $params = ($list | ForEach-Object { [uri]::EscapeDataString($_) }) -join ","
  $IgnoreContent = Invoke-WebRequest -Uri "https://www.toptal.com/developers/gitignore/api/$params" | select -ExpandProperty content 
  Out-File  -InputObject $IgnoreContent -FilePath $(Join-Path -path $pwd -ChildPath ".gitignore") -Encoding ascii
}
