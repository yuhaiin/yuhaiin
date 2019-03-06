import java.util.Base64.getUrlDecoder
//import java.io._
import scala.io.Source
import scala.io.StdIn

object base64d {
  def base64d(str: String): String = {
    val decode = new String(getUrlDecoder.decode((str + "=" * (4 - str.length)).getBytes()))
    decode
  }

  def srr_link_split(str: String): Array[String] = {
    val lines = Source.fromFile(str).getLines
    val lines_2 = base64d(lines.next).replaceAll("ssr://", "").split("\n")
    val line_base64d = new Array[String](lines_2.length)
    for (num <- line_base64d.indices) line_base64d(num) = base64d(lines_2(num))
      .replace("/?obfsparam=",":").replace("&protoparam=",":")
      .replace("&remarks=",":").replace("&group=",":")
    line_base64d
  }

  def ssr_list_remarks(line_base64d:Array[String]): Unit ={
    for(num <- line_base64d.indices){
      val line_temp = line_base64d(num).split(":")
      print(num+"."+base64d(line_temp(line_temp.length-2))+"\n")
    }
  }

  def menu(): Unit ={
    print(
      "1.start ssr\n"+
      "2.update config\n"+
      "3.deplay test\n"+
      ">> "
    )
    val num = StdIn.readLine
    print(num)
  }

  def main(args: Array[String]): Unit = {
    ssr_list_remarks(srr_link_split("/home/asutorufa/.cache/SSRSub/config.txt"))
    menu()
  }
}