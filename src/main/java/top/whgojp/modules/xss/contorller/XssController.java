package top.whgojp.modules.xss.contorller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @description xss接口
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/4/18 15:00
 */
@Controller
@RequestMapping("/xss")
public class XssController {
    // TODO: 2024/4/18 是否认证校验
    @GetMapping({"","/home"})
    public String home(){
        return "index";
    }

    //反射型XSS
    @GetMapping({"/reflect"})
    @ResponseBody
    public String reflect(@RequestParam(value = "param",required = false,defaultValue = "<script>alert(1)</script>") String param){
        return param;
    }

    //存储型XSS
    @GetMapping("store")
    public void store(@RequestParam(value = "param",required = false) String param){

    }


}
