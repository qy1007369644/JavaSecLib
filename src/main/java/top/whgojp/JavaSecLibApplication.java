package top.whgojp;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableScheduling;

@Slf4j
@SpringBootApplication(scanBasePackages = {"top.whgojp"})
public class JavaSecLibApplication {

    public static void main(String[] args) {
        SpringApplication.run(JavaSecLibApplication.class, args);
        log.info("==================JavaSecLib启动成功🤔️^-^==================");
    }

}
