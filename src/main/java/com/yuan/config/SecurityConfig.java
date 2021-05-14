package com.yuan.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //链式编程 授权
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //首页所有人可以访问，功能页只有对应有权限的人才能访问
        http.authorizeRequests().
                antMatchers("/").permitAll().
                antMatchers("/level1/**").hasRole("vip1").
                antMatchers("/level2/**").hasRole("vip2").
                antMatchers("/level3/**").hasRole("vip3");//不同的页面赋予的权限不一样
        http.formLogin().loginPage("/toLogin").loginProcessingUrl("/login");//没有权限到默认登录页面,可以设置到自己的登录页面
        //关闭csrf功能
        http.csrf().disable();
        //开启注销功能
        http.logout().logoutSuccessUrl("/");//注销之后跳转到首页
        //开启记住我功能 本质上就是cookie ，默认保持两周
        http.rememberMe();

    }

    //认证 spring security5.0+密码需要加密
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("kuangshen").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2")
                .and()
                .withUser("root").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2","vip3")
                .and()
                .withUser("guest").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1");
    }











}
