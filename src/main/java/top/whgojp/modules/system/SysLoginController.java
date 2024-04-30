package top.whgojp.modules.system;

import com.suke.zhjg.common.autofull.util.R;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import springfox.documentation.annotations.ApiIgnore;

/**
 * @description 系统登录模块
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/4/18 16:08
 */
@Controller
@Slf4j
public class SysLoginController {
    //首页
    @GetMapping(value = {"", "/","/index"})
    public String index(){
        log.info("访问了index接口");
        return "/page/login-1.html";
    }

    @RequestMapping("/user/login")
    public String login(){
        return "/login";
    }
    @RequestMapping("/user/logout")
    public String logout(){
        return "/logout";
    }

    //需要注意的是 当接口上使用@ApiIgnore注解时 此接口并不会呈现到文档上
    //比如一些/user/delete 等敏感接口 这里需要注意一下
    @ApiIgnore
    @GetMapping("/user/delete")
    public R userDelete(){
        return R.ok("此接口不在文档中");
    }

}
