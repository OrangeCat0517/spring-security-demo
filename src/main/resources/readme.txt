Spring Boot 3.0.6

一、基本概念
1. Authentication身份验证表示应用程序识别试图使用他的用户的过程
2. Authorization授权是确定经过身份验证的调用者是否具有使用特定功能和数据的权限的过程
3. Session Fixation会话固定漏洞是Web应用程序的一个漏洞，如果存在该漏洞，攻击者就可以通过重用以前生成的会话ID来模拟有效用户。
4. cross-site scripting跨站脚本也称为XSS，它允许将客户端脚本注入服务器公开的Web服务中，从而允许其它用户运行这些脚本
5. CSRF跨站请求伪造，这种攻击会恶意利用可以从应用程序外部提取并重复使用能够调用特定服务器上操作的URI。如果服务器信任该只ing而不检查请求的来源，那么恶意攻击者就可以从任何其他地方执行其操作。

二、入门
1. 添加Spring Security和MVC等依赖，
@RestController
public class HelloController {
    @GetMapping("/hello")
    public String hello() {
        return "Hello!";
    }
}
此时，运行项目后会在控制台得到密码
Using generated security password: 2b55de9e-d9fc-45d5-b455-5bc67cdac9ec

curl http://localhost:12345/hello 无结果，浏览器访问会弹出默认登录窗口，此时的默认用户名是user，密码在项目中已经生成。
curl -u user:2b55de9e-d9fc-45d5-b455-5bc67cdac9ec http://localhost:12345/hello 会得到争取结果Hello!
or
echo -n user:2b55de9e-d9fc-45d5-b455-5bc67cdac9ec | base64 得到结果 dXNlcjoyYjU1ZGU5ZS1kOWZjLTQ1ZDUtYjQ1NS01YmM2N2NkYWM5ZWM=

curl -H "Authorization: Basic dXNlcjoyYjU1ZGU5ZS1kOWZjLTQ1ZDUtYjQ1NS01YmM2N2NkYWM5ZWM=" localhost:12345/hello
The result of the call is
Hello!
注意Base64并非加密
此时Spring Security已经提供了各种默认配置：
• The authentication filter delegates the authentication request to the authentication manager and, based on the response, configures the security context.
• The authentication manager uses the authentication provider to process authentication.
• The authentication provider implements the authentication logic.
• The user details service implements user management responsibility, which the authentication provider uses in the authentication logic.
• The password encoder implements password management, which the authentication provider uses in the authentication logic.
• The security context keeps the authentication data after the authentication process.



2. 内存用户验证
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    SecurityFilterChain configure(HttpSecurity http)throws Exception {
        http.httpBasic();
        http.authorizeHttpRequests().anyRequest().authenticated();
        var user = User.withUsername("peter")
                .password("123456")
                .authorities("read")
                .build();
        var userDetailsService = new InMemoryUserDetailsManager(user);
        http.userDetailsService(userDetailsService);
        return http.build();
    }
    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
此时Spring Security会生成默认的密码，我们的自定义密码也可以生效
HTTP Basic身份验证不提供凭据的保密性支持，Base54只是一种方便传输的编码方法，并不是加密的或者Hash方法，在传输中如果被拦截可能造成任何人获取到凭据。
Https是一种保密的特性，但是不应该仅仅依赖这种特性。

3. Defining custom authentication logic 重写验证逻辑
上一个例子中的代码将验证逻辑和Spring Security混合在一起，但是更好的办法是实现AuthenticationProvider接口来完成自定义配置。
AuthenticationProvider实现了身份验证逻辑并且委托给UserDetailsService和PasswordEncoder进行密码和用户管理，此时我们不再需要UserDetailsService和PasswordEncoder。
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = String.valueOf(authentication.getCredentials());
        if ("peter".equals(username) && "123456".equals(password)) {
            return new UsernamePasswordAuthenticationToken(username, password, List.of());
        } else {
            throw new AuthenticationCredentialsNotFoundException("Error!");
        }
    }

    @Override
    public boolean supports(Class<?> authenticationType) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authenticationType);
    }
}
之后需要在SecurityConfig中注册我们的自定义认证逻辑
import com.example.springsecuritydemo.security.CustomAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    private final CustomAuthenticationProvider authenticationProvider;
    public SecurityConfig(CustomAuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }
    @Bean
    SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http.httpBasic();
        http.authenticationProvider(authenticationProvider);
        http.authorizeHttpRequests().anyRequest().authenticated();
        return http.build();
    }
}
此时Spring Security已经不再生成默认密码
curl -u peter:123456 localhost:12345/hello 也可以得到正确结果Hello!

4. Using multiple configuration classes
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class UserManagementConfig {
    @Bean
    public UserDetailsService userDetailsService() {
        var userDetailsService = new InMemoryUserDetailsManager();
        var user = User.withUsername("peter")
                .password("123456")
                .authorities("read")
                .build();
        userDetailsService.createUser(user);
        return userDetailsService;
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class WebAuthorizationConfig {
    @Bean
    SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http.httpBasic();
        http.authorizeHttpRequests().anyRequest().authenticated();
        return http.build();
    }
}

三、用户
1. 常见接口和类的总结
• UserDetails接口表示契约，其中的方法用于返回用户凭证，返回权限的集合以及账户过期、锁定账户、凭据过期、禁用账户
• UserDetailsService负责按照用户名检索用户
• UserDetailsManager添加了添加，修改，删除用户的行为，是UserDetailsService的子接口
• GrantedAuthority契约用于描述Spring Security中的权限。Spring Security使用权限指代细粒度的权限或者角色，角色也就是权限的分组。要创建一个权限只需要为其指定一个名称
• SimpleGrantedAuthority类提供了一种创建GrantedAuthority类型的不可变实例的方法。
  GrantedAuthority grantedAuthority = ()->"READ";
  grantedAuthority = new SimpleGrantedAuthority("READ");

2. 针对UserDetails的良好实现
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    private int id;
    private String username;
    private String password;
    private String authority;
}

package com.example.springsecuritydemo.security;

import com.example.springsecuritydemo.domain.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public class SecurityUser implements UserDetails {
    private final User user;

    public SecurityUser(User user) {
        this.user = user;
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }


    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(user::getAuthority);
    }


    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

3. UserDetailService契约的实现
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;

public class InMemoryUserDetailsService implements UserDetailsService {
    private final List<UserDetails> users;

    public InMemoryUserDetailsService(List<UserDetails> users) {
        this.users = users;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return users.stream()
                .filter(u -> u.getUsername().equals(username)) //从用户列表中筛选具有请求用户名的用户
                .findFirst() //如果该用户存在则返回它
                .orElseThrow(() -> new UsernameNotFoundException("User not found")); //不存在抛异常
    }
}


import com.example.springsecuritydemo.domain.User;
import com.example.springsecuritydemo.security.InMemoryUserDetailsService;
import com.example.springsecuritydemo.security.SecurityUser;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;


@Configuration
public class UserManagementConfig {
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = new SecurityUser(new User(1, "peter", "123456", "read"));
        List<UserDetails> users = List.of(userDetails);
        return new InMemoryUserDetailsService(users);
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
curl -u peter:123456 localhost:12345/hello


4. UserDetailManager契约的实现
该类的常见实现有InMemoryUserDetailsManager，JdbcUserDetailsManager等。下面采用JdbcUserDetailsManager对接DB中的用户。为此需要准备表格如下：
DROP TABLE IF EXISTS `users`;
DROP TABLE IF EXISTS `authorities`;

CREATE TABLE IF NOT EXISTS `users`
(
    `id`       INT         NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(45) NOT NULL,
    `password` VARCHAR(45) NOT NULL,
    `enabled`  INT         NOT NULL,
    PRIMARY KEY (`id`)
);

CREATE TABLE IF NOT EXISTS `authorities`
(
    `id`        INT         NOT NULL AUTO_INCREMENT,
    `username`  VARCHAR(45) NOT NULL,
    `authority` VARCHAR(45) NOT NULL,
    PRIMARY KEY (`id`)
);

INSERT INTO `authorities` (username, authority) VALUES ('john', 'write');
INSERT INTO `users` (username, password, enabled) VALUES ('john', '12345', '1');


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import javax.sql.DataSource;
@Configuration
public class UserManagementConfig {
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        String usersByUsernameQuery = "select username, password, enabled from test.users where username = ?";
        String authsByUserQuery = "select username, authority from test.authorities where username = ?";
        var userDetailsManager = new JdbcUserDetailsManager(dataSource);
        userDetailsManager.setUsersByUsernameQuery(usersByUsernameQuery);
        userDetailsManager.setAuthoritiesByUsernameQuery(authsByUserQuery);
        return userDetailsManager;
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}

四、密码
1. 各种加密策略和算法
• NoOpPasswordEncoder           明文，过时
• StandardPasswordEncoder       SHA-256对密码哈希化，过时
• Pbkdf2PasswordEncoder         使用基于密码的密钥派生函数2(PBKDF2)
• BCryptPasswordEncoder         使用bcrypt强哈希函数对密码进行编码
• SCryptPasswordEncoder         使用scrypt哈希函数对密码进行编码

2. 使用DelegatingPasswordEncoder实现多种编码策略
@Bean
public PasswordEncoder passwordEncoder() {
    Map<String, PasswordEncoder> encoders = new HashMap<>();
    encoders.put("noop", NoOpPasswordEncoder.getInstance());  //注意数据库中的密码必须是{noop}123456
    encoders.put("bcrypt", new BCryptPasswordEncoder());
    encoders.put("scrypt", new SCryptPasswordEncoder(16384, 8, 1, 12, 64));
    return new DelegatingPasswordEncoder("bcrypt", encoders);
}
以上密码加密后，数据库中的密码必须使用{}跟上map中的key作为前缀，以便Spring Security进行选择
@Bean
public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
}  //采用默认的bcrypt

3. 编码，加密，哈希化
3.1 编码仅仅指的是一种转换。
3.2 加密是一种特殊类型的编码，需要同时提供输入和密钥。这个密钥使我们可以选择谁应该能够进行逆向函数。一个人知道了密钥就可以使用一个已知的函数从输出推导回输入的原始密码，我们称之为逆向函数解密。如果用于加密和解密的密钥相同，我们称为对称加密。
如果加密和解密使用连个不同的密钥，我们称为非对称加密。此时加密和解密的密钥称为密钥对，用于加密的密钥称为公钥，用于解密的密钥为私钥。这样，只有持有私钥的所有者才可以完成解密。
3.3 哈希化是一种特殊类型的编码，只不过其函数是单向的。 也就是无法从输出结果中得到x。但是总有一种方法检查输出y是否对应输入x。
因此可以把哈希理解为一对进行编码和匹配的函数。
有时哈希函数也可以使用额外添加得到输出，这个额外添加被称为salt。salt会让哈希更强大，他增加了应用逆向函数从结果中获取输入的难度。

4. Spring Security Crypto
4.1 密钥生成器
有两个接口ByteKeyGenerator和StringKeyGenerator表示两种主要类型的密钥生成器。可以使用工厂类KeyGenerators直接构建它们。
通常我们使用这个结果用作哈希化或加密算法的salt

4.2 用密钥生成器进行加密和解密



五、身份验证逻辑


