import java.util.Base64.getUrlDecoder
//import java.io._
import scala.io.Source

object base64d {
  def base64d(str : String):String={
  val decode = new String(getUrlDecoder.decode((str+"="*(4-str.length)).getBytes()))
  return decode
}

def srr_link_split(str : String):Array[String] = {
  val lines = Source.fromFile(str).getLines
  val lines_2 = base64d(lines.next).replaceAll("ssr://","").split("\n")
  val line_base64d = new Array[String](lines_2.length)
  for(num <- 0 until line_base64d.length) line_base64d(num) = base64d(lines_2(num))
  return line_base64d
}
  def main(args: Array[String]): Unit = {
    val lines = srr_link_split("/home/asutorufa/.cache/SSRSub/config.txt")
    for(line <- lines) print(line+"\n")
  }
}
