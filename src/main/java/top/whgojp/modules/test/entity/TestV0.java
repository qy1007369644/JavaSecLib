package top.whgojp.modules.test.entity;

import lombok.Data;

import java.util.Date;
import java.util.List;

/**
 * @description 测试实体类
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/4/27 11:04
 */
@Data
public class TestV0 {
    private String username;
    private Integer age;
    private Integer sex;
    private Boolean isVip;
    private Date createTime;
    private List<String> tags;
}
