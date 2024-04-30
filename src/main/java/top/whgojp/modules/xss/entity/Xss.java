package top.whgojp.modules.xss.entity;

import java.io.Serializable;
import lombok.Data;

/**
 * 
 * @TableName xss
 */
@Data
public class Xss implements Serializable {
    /**
     * 
     */
    private Integer id;

    /**
     * 
     */
    private String user;

    /**
     * 
     */
    private String content;

    /**
     * 
     */
    private String date;

    private static final long serialVersionUID = 1L;
}