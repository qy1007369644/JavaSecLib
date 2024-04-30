package top.whgojp.modules.test.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import top.whgojp.modules.test.entity.TestV0;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

/**
 * @description 测试接口
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/4/26 21:31
 */
@Controller
@RequestMapping("/test")
public class TestController {
    @GetMapping("/01")
    @ResponseBody
    public String test01(){
        return "<u>A</u>";
    }
    @GetMapping("/02")
    public String test02(Model model){
        model.addAttribute("title","th-title");
        final TestV0 testV0 = new TestV0();
        testV0.setUsername("whgojp");
        testV0.setSex(1);
        testV0.setAge(22);
        testV0.setCreateTime(new Date());
        testV0.setTags(Arrays.asList("Java","PHP","Golang"));
        model.addAttribute("testV0",testV0);
        return "test";
    }


}
