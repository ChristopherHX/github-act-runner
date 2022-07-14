param ($Worker)
# This script can be used to call Runner.Worker as github-act-runner worker
$stdin = [System.Console]::OpenStandardInput()
$pipeOut = New-Object -TypeName System.IO.Pipes.AnonymousPipeServerStream -ArgumentList 'Out','Inheritable'
$pipeIn = New-Object -TypeName System.IO.Pipes.AnonymousPipeServerStream -ArgumentList 'In','Inheritable'
if($Worker.EndsWith(".dll")) {
    $proc = Start-Process -NoNewWindow -PassThru -FilePath dotnet -ArgumentList $Worker,spawnclient,$pipeOut.GetClientHandleAsString(),$pipeIn.GetClientHandleAsString()
} else {
    $proc = Start-Process -NoNewWindow -PassThru -FilePath $Worker -ArgumentList spawnclient,$pipeOut.GetClientHandleAsString(),$pipeIn.GetClientHandleAsString()
}
$buf = New-Object byte[] 4
while( -Not $proc.HasExited ) {
    $asyncRead = $stdin.ReadAsync($buf, 0, 4)
    while((-not $asyncRead.AsyncWaitHandle.WaitOne(200)) -and (-Not $proc.HasExited)) { }
    if($proc.HasExited) {
        return
    }
    $null = $asyncRead.GetAwaiter().GetResult()
    $messageType = [System.Buffers.Binary.BinaryPrimitives]::ReadInt32BigEndian($buf)
    $stdin.Read($buf, 0, 4)
    $contentLength = [System.Buffers.Binary.BinaryPrimitives]::ReadInt32BigEndian($buf)
    $rawcontent = New-Object byte[] $contentLength
    $stdin.Read($rawcontent, 0, $contentLength)
    $utf8Content = [System.Text.Encoding]::UTF8.GetString($rawcontent)
    $content = [System.Text.Encoding]::Unicode.GetBytes($utf8Content)
    $pipeOut.Write([BitConverter]::GetBytes($messageType), 0, 4)
    $pipeOut.Write([BitConverter]::GetBytes($content.Length), 0, 4)
    $pipeOut.Write($content, 0, $content.Length)
    $pipeOut.Flush()
}
$pipeOut.Dispose()
$pipeIn.Dispose()