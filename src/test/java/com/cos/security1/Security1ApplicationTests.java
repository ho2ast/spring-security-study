package com.cos.security1;

import com.cos.security1.config.SecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

@SpringBootTest
class Security1ApplicationTests {

    @Test
    void contextLoads() {
        AnnotationConfigApplicationContext applicationContext = new AnnotationConfigApplicationContext(SecurityConfig.class);

        String[] beanDefinitionNames = applicationContext.getBeanDefinitionNames();

        for (String beanDefinitionName : beanDefinitionNames) {

            BeanDefinition beanDefinition = applicationContext.getBeanDefinition(beanDefinitionName);
            if (beanDefinition.getRole() == BeanDefinition.ROLE_APPLICATION) {
                Object bean = applicationContext.getBean(beanDefinitionName);
                System.out.println("beanDefinitionName = " + beanDefinitionName + "asdasdsad" + bean);
            }
        }
    }

}
