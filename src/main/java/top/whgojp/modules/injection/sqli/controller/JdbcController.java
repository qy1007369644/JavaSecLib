package top.whgojp.modules.injection.sqli.controller;

import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import com.suke.zhjg.common.autofull.util.R;
import io.swagger.annotations.*;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.codecs.OracleCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.web.bind.annotation.*;

import java.sql.*;
import java.util.Map;

/**
 * @description sql注入-JDBC原生操作
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/4/27 21:46
 */
@Api(value = "JdbcController", tags = "SQL注入-JDBC")
@RestController
@RequestMapping("/sqli/jdbc")
public class JdbcController {
    Logger log = LoggerFactory.getLogger(JdbcController.class);

    //指定数据库地址、用户名、密码
    @Value("${spring.datasource.url}")
    private String dbUrl;
    @Value("${spring.datasource.username}")
    private String dbUser;
    @Value("${spring.datasource.password}")
    private String dbPass;

    @ApiOperation(value = "漏洞环境：JDBC-原生SQL语句拼接",notes = "原生sql语句动态拼接 参数未进行任何处理")
    @GetMapping("/vul1-raw-joint")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query",dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", required = false, dataType = "String", paramType = "query",dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", required = false, dataType = "String", paramType = "query",dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", required = false, dataType = "String", paramType = "query",dataTypeClass = String.class)
    })
    public R vul1RawJoint(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) String id,
            @ApiParam(name = "username", value = "用户名") @RequestParam(required = false) String username,
            @ApiParam(name = "password", value = "密码") @RequestParam(required = false) String password){
        String sql = "";
        try {
            //注册数据库驱动类
            Class.forName("com.mysql.cj.jdbc.Driver");

            //调用DriverManager.getConnection()方法创建Connection连接到数据库
            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);

            //调用Connection的createStatement()或prepareStatement()方法 创建Statement对象
            Statement stmt = conn.createStatement();
            int rowsAffected;
            switch (type) {
                case "add":
                    //数据校验
                    if (username == null || password == null) return R.error("username或password为空");
                    sql = "INSERT INTO users (user, pass) VALUES ('" + username + "', '" + password + "')";
                    log.info("当前执行数据插入操作:" + sql);
                    //通过Statement对象执行SQL语句，得到ResultSet对象-查询结果集
                    rowsAffected = stmt.executeUpdate(sql);         // 这里注意一下 insert、update、delete 语句应使用executeUpdate()
                    //关闭ResultSet结果集 Statement对象 以及数据库Connection对象 释放资源
                    stmt.close();
                    conn.close();
                    if (rowsAffected > 0) {
                        log.info("数据插入成功");
                        return R.ok("数据插入成功");
                    } else {
                        log.info("数据插入失败");
                        return R.ok("数据插入失败");
                    }
                case "delete":
                    sql = "DELETE FROM users WHERE id = '" + id + "'";
                    log.info("当前执行数据删除操作:" + sql);
                    rowsAffected = stmt.executeUpdate(sql);
                    stmt.close();
                    conn.close();
                    if (rowsAffected > 0) {
                        log.info("数据删除成功");
                        return R.ok("数据删除成功");
                    } else {
                        log.info("数据删除失败");
                        return R.ok("数据删除失败");
                    }
                case "update":
                    sql = "UPDATE users set pass = '" + password + "' where id = '" + id + "'";
                    log.info("当前执行数据更新操作:" + sql);
                    rowsAffected = stmt.executeUpdate(sql);
                    stmt.close();
                    conn.close();
                    if (rowsAffected > 0) {
                        log.info("数据更新成功");
                        return R.ok("数据更新成功");
                    } else {
                        log.info("数据更新失败");
                        return R.ok("数据更新失败");
                    }
                case "select":
                    sql = "SELECT * FROM users WHERE id  = " + id;
                    log.info("当前执行数据查询操作:" + sql);
                    //通过Statement对象执行SQL语句，得到ResultSet对象-查询结果集
                    ResultSet rs = stmt.executeQuery(sql);
                    //遍历ResultSet 从结果集中读取数据 并将没一行数据库记录转换成Javabean对象
                    while (rs.next()) {
                        String user = rs.getString("user");
                        String pass = rs.getString("pass");
                        final JSONObject jsonObject = JSONUtil.createObj();
                        jsonObject.put("username", user);
                        jsonObject.put("password", pass);
                    }
                    stmt.close();
                    conn.close();
                default:
                    return R.error("type字段有误：传输数据异常,请检查^_^");
            }

        } catch (Exception e) {
            return R.error(e.toString());
        }
    }

    /**
     * 在执行DML操作时 上述步骤都会重复出现(重复建立、释放连接) 为了简化重复逻辑 提供代码可维护性
     * 后续发展使用ORM(Object Relational Mapping 对象-关系映射)框架来封装以上重复代码(使用数据库连接池、缓存等技术)
     * 实现对象模型、关系模型之间的转换 ORM框架的核心功能：根据配置配置文件or注解) 实现对象模型、关系模型之间的映射
     * 常用ORM框架：Hibernate、MyBatis、JPA
     */

    @ApiOperation(value = "漏洞环境：JDBC-预编译拼接", notes = "虽然使用了 conn.prepareStatement(sql) 创建了一个 PreparedStatement 对象，但在执行 stmt.executeUpdate(sql) 时，却是传递了完整的 SQL 语句作为参数，而不是使用了预编译的功能")
    @GetMapping("/vul2-prepareStatement-joint")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query",dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", required = false, dataType = "String", paramType = "query",dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", required = false, dataType = "String", paramType = "query",dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", required = false, dataType = "String", paramType = "query",dataTypeClass = String.class)
    })
    public R vul2prepareStatementJoint(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) String id,
            @ApiParam(name = "username", value = "用户名") @RequestParam(required = false) String username,
            @ApiParam(name = "password", value = "密码") @RequestParam(required = false) String password) {
        {
            String sql = "";
            try {
                Class.forName("com.mysql.cj.jdbc.Driver");

                Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);
                PreparedStatement stmt;
                int rowsAffected;
                switch (type) {
                    case "add":
                        if (username == null || password == null) return R.error("username或password为空");
                        sql = "INSERT INTO users (user, pass) VALUES ('" + username + "', '" + password + "')";
                        log.info("当前执行数据插入操作:" + sql);
                        stmt = conn.prepareStatement(sql);
                        rowsAffected = stmt.executeUpdate(sql);
                        stmt.close();
                        conn.close();
                        if (rowsAffected > 0) {
                            log.info("数据插入成功");
                            return R.ok("数据插入成功");
                        } else {
                            log.info("数据插入失败");
                            return R.ok("数据插入失败");
                        }
                    case "delete":
                        sql = "DELETE FROM users WHERE id = '" + id + "'";
                        log.info("当前执行数据删除操作:" + sql);
                        stmt = conn.prepareStatement(sql);
                        rowsAffected = stmt.executeUpdate(sql);
                        stmt.close();
                        conn.close();
                        if (rowsAffected > 0) {
                            log.info("数据删除成功");
                            return R.ok("数据删除成功");
                        } else {
                            log.info("数据删除失败");
                            return R.ok("数据删除失败");
                        }
                    case "update":
                        sql = "UPDATE users set pass = '" + password + "' where id = '" + id + "'";
                        log.info("当前执行数据更新操作:" + sql);
                        stmt = conn.prepareStatement(sql);
                        rowsAffected = stmt.executeUpdate(sql);
                        stmt.close();
                        conn.close();
                        if (rowsAffected > 0) {
                            log.info("数据更新成功");
                            return R.ok("数据更新成功");
                        } else {
                            log.info("数据更新失败");
                            return R.ok("数据更新失败");
                        }
                    case "select":
                        sql = "SELECT * FROM users WHERE id  = " + id;
                        log.info("当前执行数据查询操作:" + sql);
                        stmt = conn.prepareStatement(sql);
                        ResultSet rs = stmt.executeQuery(sql);
                        while (rs.next()) {
                            String res_name = rs.getString("user");
                            String res_pass = rs.getString("pass");
                            String info = String.format("查询结果%n %s: %s%n", res_name, res_pass);
                            return R.ok(info);
                        }
                        stmt.close();
                        conn.close();
                    default:
                        return R.error("type字段有误：传输数据异常,请检查^_^");
                }

            } catch (Exception e) {
                return R.error(e.toString());
            }
        }
    }

    @ApiOperation(value = "漏洞环境：JdbcTemplate-SQL语句拼接", notes = "JDBCTemplate是Spring对JDBC的封装，底层实现实际上还是JDBC")
    @GetMapping("/vul3-JdbcTemplate-joint")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query",dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", required = false, dataType = "String", paramType = "query",dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", required = false, dataType = "String", paramType = "query",dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", required = false, dataType = "String", paramType = "query",dataTypeClass = String.class)
    })
    public R vul3JdbcTemplateJoint(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) String id,
            @ApiParam(name = "username", value = "用户名") @RequestParam(required = false) String username,
            @ApiParam(name = "password", value = "密码") @RequestParam(required = false) String password) {
        String sql = "";
        try {
            DriverManagerDataSource dataSource = new DriverManagerDataSource();
            dataSource.setDriverClassName("com.mysql.cj.jdbc.Driver");
            dataSource.setUrl(dbUrl);
            dataSource.setUsername(dbUser);
            dataSource.setPassword(dbPass);
            JdbcTemplate jdbctemplate = new JdbcTemplate(dataSource);

            int rowsAffected;
            switch (type) {
                case "add":
                    if (username == null || password == null) return R.error("username或password为空");
                    sql = "INSERT INTO users (user, pass) VALUES ('" + username + "', '" + password + "')";
                    log.info("当前执行数据插入操作:" + sql);
                    rowsAffected = jdbctemplate.update(sql);        //SPring的JdbcTemplate会自动管理连接的获取和释放，不出油手动关闭连接
                    if (rowsAffected > 0) {
                        log.info("数据插入成功");
                        return R.ok("数据插入成功");
                    } else {
                        log.info("数据插入失败");
                        return R.ok("数据插入失败");
                    }
                case "delete":
                    sql = "DELETE FROM users WHERE id = '" + id + "'";
                    log.info("当前执行数据删除操作:" + sql);
                    rowsAffected = jdbctemplate.update(sql);
                    if (rowsAffected > 0) {
                        log.info("数据删除成功");
                        return R.ok("数据删除成功");
                    } else {
                        log.info("数据删除失败");
                        return R.ok("数据删除失败");
                    }
                case "update":
                    sql = "UPDATE users set pass = '" + password + "' where id = '" + id + "'";
                    log.info("当前执行数据更新操作:" + sql);
                    rowsAffected = jdbctemplate.update(sql);
                    if (rowsAffected > 0) {
                        log.info("数据更新成功");
                        return R.ok("数据更新成功");
                    } else {
                        log.info("数据更新失败");
                        return R.ok("数据更新失败");
                    }
                case "select":
                    sql = "SELECT * FROM users WHERE id  = " + id;
                    log.info("当前执行数据查询操作:" + sql);
                    final Map<String, Object> stringObjectMap = jdbctemplate.queryForMap(sql);
                    final JSONObject jsonObject = JSONUtil.createObj();
                    jsonObject.put("result",stringObjectMap);
                    return R.ok(jsonObject);

                default:
                    return R.error("type字段有误：传输数据异常,请检查^_^");
            }

        } catch (Exception e) {
            return R.error(e.toString());
        }
    }

    @ApiOperation(value = "安全代码：JDBC预编译", notes = "采用预编译的方法，使用?占位，也叫参数化的SQL")
    @GetMapping("/safe1-PrepareStatement-Parametric")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query",dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", required = false, dataType = "String", paramType = "query",dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", required = false, dataType = "String", paramType = "query",dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", required = false, dataType = "String", paramType = "query",dataTypeClass = String.class)
    })
    public R safe1PrepareStatementParametric(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) String id,
            @ApiParam(name = "username", value = "用户名") @RequestParam(required = false) String username,
            @ApiParam(name = "password", value = "密码") @RequestParam(required = false) String password) {
        String sql = "";
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");

            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);
            PreparedStatement stmt;
            int rowsAffected;
            switch (type) {
                case "add":
                    if (username == null || password == null) return R.error("username或password为空");

                    sql = "INSERT INTO users (user, pass) VALUES (?, ?)";   // 这里可以看到使用了?占位符 sql语句和参数进行分离
                    log.info("当前执行数据插入操作:" + sql);
                    stmt = conn.prepareStatement(sql);
                    stmt.setString(1, username);                // 参数化处理
                    stmt.setString(2, password);

                    rowsAffected = stmt.executeUpdate();                    // 使用预编译时 不需要传递sql语句
                    stmt.close();
                    conn.close();
                    if (rowsAffected > 0) {
                        log.info("数据插入成功");
                        return R.ok("数据插入成功");
                    } else {
                        log.info("数据插入失败");
                        return R.ok("数据插入失败");
                    }
                case "delete":
                    sql = "DELETE FROM users WHERE id = ?";
                    log.info("当前执行数据删除操作:" + sql);
                    stmt = conn.prepareStatement(sql);
                    stmt.setString(1, id.toString());

                    rowsAffected = stmt.executeUpdate();
                    stmt.close();
                    conn.close();
                    if (rowsAffected > 0) {
                        log.info("数据删除成功");
                        return R.ok("数据删除成功");
                    } else {
                        log.info("数据删除失败");
                        return R.ok("数据删除失败");
                    }
                case "update":
                    sql = "UPDATE users set pass = ? where id = ?";
                    log.info("当前执行数据更新操作:" + sql);
                    stmt = conn.prepareStatement(sql);
                    stmt.setString(1, password);
                    stmt.setString(2, id);

                    rowsAffected = stmt.executeUpdate();
                    stmt.close();
                    conn.close();
                    if (rowsAffected > 0) {
                        log.info("数据更新成功");
                        return R.ok("数据更新成功");
                    } else {
                        log.info("数据更新失败");
                        return R.ok("数据更新失败");
                    }
                case "select":
                    sql = "SELECT * FROM users WHERE id  = ?";
                    log.info("当前执行数据查询操作:" + sql);
                    stmt = conn.prepareStatement(sql);
                    stmt.setString(1, id);
                    ResultSet rs = stmt.executeQuery();
                    final JSONObject result = JSONUtil.createObj();
                    while (rs.next()) {
                        String user = rs.getString("user");
                        String pass = rs.getString("pass");
                        final JSONObject jsonObject = JSONUtil.createObj();
                        jsonObject.put("username", user);
                        jsonObject.put("password", pass);
                        result.put("result", jsonObject);
                        return R.ok(result);
                    }
                    stmt.close();
                    conn.close();
                default:
                    return R.error("type字段有误：传输数据异常,请检查^_^");
            }

        } catch (Exception e) {
            return R.error(e.toString());
        }
    }

    @ApiOperation(value = "安全代码：JdbcTemplate预编译", notes = "JDBCTemplate预编译 此时在常规DML场景有效的防止了SQL注入攻击的发生")
    @GetMapping("/safe-JdbcTemplate-PrepareStatement-Parametric")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "type", value = "操作类型", required = true, dataType = "String", paramType = "query",dataTypeClass = String.class),
            @ApiImplicitParam(name = "id", value = "用户ID", required = false, dataType = "String", paramType = "query",dataTypeClass = String.class),
            @ApiImplicitParam(name = "username", value = "用户名", required = false, dataType = "String", paramType = "query",dataTypeClass = String.class),
            @ApiImplicitParam(name = "password", value = "密码", required = false, dataType = "String", paramType = "query",dataTypeClass = String.class)
    })
    public R safe2JdbcTemplatePrepareStatementParametric(
            @ApiParam(name = "type", value = "操作类型", required = true) @RequestParam String type,
            @ApiParam(name = "id", value = "用户ID") @RequestParam(required = false) String id,
            @ApiParam(name = "username", value = "用户名") @RequestParam(required = false) String username,
            @ApiParam(name = "password", value = "密码") @RequestParam(required = false) String password) {
        String sql = "";
        try {
            DriverManagerDataSource dataSource = new DriverManagerDataSource();
            dataSource.setDriverClassName("com.mysql.cj.jdbc.Driver");
            dataSource.setUrl(dbUrl);
            dataSource.setUsername(dbUser);
            dataSource.setPassword(dbPass);
            JdbcTemplate jdbctemplate = new JdbcTemplate(dataSource);

            int rowsAffected;
            switch (type) {
                case "add":
                    if (username == null || password == null) return R.error("username或password为空");
                    sql = "INSERT INTO users (user, pass) VALUES (?,?)";
                    log.info("当前执行数据插入操作:" + sql);
                    rowsAffected = jdbctemplate.update(sql,username,password);
                    if (rowsAffected > 0) {
                        log.info("数据插入成功");
                        return R.ok("数据插入成功");
                    } else {
                        log.info("数据插入失败");
                        return R.ok("数据插入失败");
                    }
                case "delete":
                    sql = "DELETE FROM users WHERE id = ?";
                    log.info("当前执行数据删除操作:" + sql);
                    rowsAffected = jdbctemplate.update(sql,id);
                    if (rowsAffected > 0) {
                        log.info("数据删除成功");
                        return R.ok("数据删除成功");
                    } else {
                        log.info("数据删除失败");
                        return R.ok("数据删除失败");
                    }
                case "update":
                    sql = "UPDATE users set pass = ? where id = ?";
                    log.info("当前执行数据更新操作:" + sql);
                    rowsAffected = jdbctemplate.update(sql,username,id);
                    if (rowsAffected > 0) {
                        log.info("数据更新成功");
                        return R.ok("数据更新成功");
                    } else {
                        log.info("数据更新失败");
                        return R.ok("数据更新失败");
                    }
                case "select":
                    sql = "SELECT * FROM users WHERE id  = ?";
                    log.info("当前执行数据查询操作:" + sql);
                    final Map<String, Object> stringObjectMap = jdbctemplate.queryForMap(sql,id);
                    final JSONObject jsonObject = JSONUtil.createObj();
                    jsonObject.put("result",stringObjectMap);
                    return R.ok(jsonObject);

                default:
                    return R.error("type字段有误：传输数据异常,请检查^_^");
            }

        } catch (Exception e) {
            return R.error(e.toString());
        }
    }

//    @ApiOperation(value = "safe：采用黑名单过滤的方式")
//    @GetMapping("/safe2")
//    public String safe2(String id) {
//
//        if (!Security.checkSql(id)) {
//
//            StringBuilder result = new StringBuilder();
//
//            try {
//                Class.forName("com.mysql.cj.jdbc.Driver");
//                Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);
//
//                Statement stmt = conn.createStatement();
//                String sql = "select * from users where id = '" + id + "'";
//                ResultSet rs = stmt.executeQuery(sql);
//                log.info("[safe] 执行SQL语句： " + sql);
//
//                while (rs.next()) {
//                    String res_name = rs.getString("user");
//                    String res_pass = rs.getString("pass");
//                    String info = String.format("查询结果%n %s: %s%n", res_name, res_pass);
//                    result.append(info);
//                }
//
//                rs.close();
//                stmt.close();
//                conn.close();
//                return result.toString();
//
//            } catch (Exception e) {
//                return e.toString();
//            }
//        } else {
//            log.warn("检测到非法注入");
//            return "检测到非法注入！";
//        }
//    }


/*    @ApiOperation(value = "safe：采用ESAPI过滤")
    @GetMapping("/safe3")
    public String safe3(String id) {
        StringBuilder result = new StringBuilder();

        try {
            Codec<Character> oracleCodec = new OracleCodec();
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);

            Statement stmt = conn.createStatement();
            String sql = "select * from users where id = '" + ESAPI.encoder().encodeForSQL(oracleCodec, id) + "'";
            log.info("[safe] 执行SQL语句： " + sql);
            ResultSet rs = stmt.executeQuery(sql);

            while (rs.next()) {
                String res_name = rs.getString("user");
                String res_pass = rs.getString("pass");
                String info = String.format("查询结果%n %s: %s%n", res_name, res_pass);
                result.append(info);
            }

            rs.close();
            stmt.close();
            conn.close();
            return result.toString();

        } catch (Exception e) {
            return e.toString();
        }
    }*/


    @ApiOperation(value = "safe：强制数据类型")
    @GetMapping("/safe4")
    public Map<String, Object> safe4(Integer id) {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("com.mysql.cj.jdbc.Driver");
        dataSource.setUrl(dbUrl);
        dataSource.setUsername(dbUser);
        dataSource.setPassword(dbPass);

        JdbcTemplate jdbctemplate = new JdbcTemplate(dataSource);

        String sql_vul = "select * from users where id = " + id;

        return jdbctemplate.queryForMap(sql_vul);
    }

    @ApiOperation(value = "特殊场景：使用prepareStatement时，order by下的sql注入问题", notes = "原理:使用prepareStatement时，order by 后面需要加字段名，字段名不能带引号，带引号会被认为这是一个字符串而不是字段名。PrepareStatement 是使用占位符传入参数的，传递的字符都会有单引号包裹，ps.setString(1, id)”会自动给值加上引号，这样就会导致 order by 子句失效。")
    @GetMapping("/special1")
    public R special1(@RequestParam String field) {
        log.info("根据" + field + "字段排序，默认升序");
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);
            String sql = "SELECT * FROM users ORDER BY " + field;
            log.info("当前执行数据排序操作：" + sql);
            final PreparedStatement preparedStatement = conn.prepareStatement(sql);
            final ResultSet rs = preparedStatement.executeQuery();
            JSONArray jsonArray = new JSONArray(); // 创建 JSON 数组来存储所有记录
            while (rs.next()) {
                String id = rs.getString("id");
                String user = rs.getString("user");
                String pass = rs.getString("pass");
                final JSONObject jsonObject = JSONUtil.createObj();
                jsonObject.put("id", id);
                jsonObject.put("username", user);
                jsonObject.put("password", pass);
                jsonArray.put(jsonObject); // 将 JSON 对象放入 JSON 数组中
            }
            JSONObject result = new JSONObject(); // 创建结果对象
            result.put("result", jsonArray); // 将 JSON 数组放入结果对象中
            return R.ok(result);
        } catch (Exception e) {
            return R.error(e.toString());
        }
    }

    @ApiOperation(value = "特殊场景：使用%和模糊查询")
    @GetMapping("/special2")
    public R special2() {
        return R.ok();
    }


}
