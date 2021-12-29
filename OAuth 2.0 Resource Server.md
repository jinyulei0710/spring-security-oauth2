# OAuth 2.0资源服务器

Spring Security 支持使用以下两种形式的OAuth 2.0 [Bearer Tokens](https://tools.ietf.org/html/rfc6750.html)来保护端点:

* [JWT](https://tools.ietf.org/html/rfc7519)
* 不透明令牌－十六进制字符串

这在应用把它的授权管理代理给一个授权服务的时候是比较方便的,资源服务器能够查询授权服务从而对请求进行授权.

这部分内容提供了　Spring Security　如何提供OAuth 2.0 [Bearer Tokens](https://tools.ietf.org/html/rfc6750.html)支持的细节.

来看下　[Bearer Tokens](https://tools.ietf.org/html/rfc6750.html)　在　Spring Security　中如何工作的。首先就像　Basic　认证一样,　[WWW-Authenticate](https://tools.ietf.org/html/rfc7235#section-4.1) 请求头也会被发送回给客户端.

![bearerauthenticationentrypoint](https://docs.spring.io/spring-security/reference/_images/servlet/oauth2/bearerauthenticationentrypoint.png)



上图建立起了 [SecurityFilterChain](https://docs.spring.io/spring-security/reference/servlet/architecture.html#servlet-securityfilterchain) 图解

1.首先，用户对私有的资源发起了未经认证的请求

2.Spring Security 的 FilterSecurityInterceptor 通过抛出　AccessDeniedException　来指示未经认证的请求被拒绝了。

3.因为用户未经认证，[`ExceptionTranslationFilter`](https://docs.spring.io/spring-security/reference/servlet/architecture.html#servlet-exceptiontranslationfilter)发起起始认证。定义好的[`AuthenticationEntryPoint`](https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html#servlet-authentication-authenticationentrypoint) 是一个[`BearerTokenAuthenticationEntryPoint`](https://docs.spring.io/spring-security/site/docs/5.6.0/api/org/springframework/security/oauth2/server/resource/web/BearerTokenAuthenticationEntryPoint.html)实例，它会发送回一个 WWW-Authenticate请求头.RequestCache通常是不保存请求的NullRequestCache，因为客户端能够重放它最初请求的请求。

当客户机接收到 WWW-Authenticate:Bearer 报头时，它知道应该使用 bearer token 重试。下面是正在处理的 bearer token 流程。

![bearertokenauthenticationfilter](https://docs.spring.io/spring-security/reference/_images/servlet/oauth2/bearertokenauthenticationfilter.png)

​                                                           图2.认证Bearer Token

该图构建了我们的　SecurityFilterChain　图。

1 当用户提交其 bearer token 时，BealerTokenAuthenticationFilter 通过从 HttpServletRequest 提取令牌来创建一个　BealerTokenAuthenticationToken，这是一种身份验证类型。

2 HttpServletRequest 被传递给 AuthenticationManagerResolver，后者选择 AuthenticationManager。BearTokenAuthenticationToken 被传递到AuthenticationManager 以进行身份验证。AuthenticationManager 外观的详细信息取决于您是配置为JWT还是不透明令牌。

3 如果身份验证失败，则进入失败分支

* SecurityContextHolder 被清除。

* 将调用　AuthenticationEntryPoint　以触发再次发送　WWW Authenticate　标头。

4 如果身份验证成功，则进入成功分支。

*　Authentication 设置到了　SecurityContextHolder　上。

*　BearTokenAuthenticationFilter　调用　FilterChain.doFilter(request,response)　继续应用程序逻辑的其余部分。

### OAuth 2.0 Resource Server JWT

#### JWT 依赖最小化

大多数资源服务器支持被收集到 spring-security-oauth2-resource-server 中。但是，对解码和验证 JWT 的支持在 spring-security-oauth2-jose 中，这意味着为了拥有支持 JWT 编码的承载令牌的工作资源服务器，两者都是必需的。

#### JWT 配置最小化

使用 Spring Boot 时，将应用程序配置为资源服务器包括两个基本步骤。首先，包括所需的依赖项，其次，指明授权服务器的位置。

##### 指定授权服务器

在 Spring Boot 应用程序中，要指定要使用的授权服务器，只需执行以下操作：

```
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://idp.example.com/issuer
```

其中 https://idp.example.com/issuer 是授权服务器将发布的 JWT 令牌的 iss 声明中包含的值。资源服务器将使用此属性进一步自我配置，发现授权服务器的公钥，并随后验证传入的 JWT。

要使用 issuer-uri 属性，还必须是 https://idp.example.com/issuer/.well-known/openid-configuration、https://idp.example.com/.well- 之一known/openid-configuration/issuer 或 https://idp.example.com/.well-known/oauth-authorization-server/issuer 是授权服务器支持的端点。此端点称为提供者配置端点或授权服务器元数据端点。

就这么多！

##### 启动期望

当使用此属性和这些依赖项时，资源服务器将自动配置自身以验证 JWT 编码的承载令牌。

它通过确定性的启动过程来实现这一点：

1 为 jwks_url 属性查询提供者配置或授权服务器元数据端点

2 查询 jwks_url 端点以获取支持的算法

3 配置验证策略以查询 jwks_url 以获取找到的算法的有效公钥

4 配置验证策略以针对 https://idp.example.com 验证每个 JWT 的 iss 声明。

此过程的结果是授权服务器必须启动并接收请求才能成功启动资源服务器。

如果授权服务器在资源服务器查询时关闭（给定适当的超时），则启动将失败。

##### 运行时期望

应用程序启动后，资源服务器将尝试处理任何包含 Authorization: Bearer 标头的请求：

```html
GET / HTTP/1.1
Authorization: Bearer some-token-value # Resource Server will process this
```

只要指明了这个方案，Resource Server 就会尝试根据 Bearer Token 规范处理请求。

给定一个格式良好的 JWT，资源服务器将：

1. 根据启动期间从 jwks_url 端点获取并与 JWT 匹配的公钥验证其签名

2. 验证 JWT 的 exp 和 nbf 时间戳以及 JWT 的 iss 声明，以及

3. 将每个范围映射到具有前缀 SCOPE_ 的权限。

当授权服务器提供新密钥时，Spring Security 将自动轮换用于验证 JWT 的密钥。

默认情况下，生成的 Authentication#getPrincipal 是 Spring Security Jwt 对象，并且 Authentication#getName 映射到 JWT 的 sub 属性（如果存在）。

#### JWT 认证是如何工作的

接下来，让我们看看 Spring Security 用于在基于 servlet 的应用程序中支持 JWT 身份验证的架构组件，就像我们刚刚看到的那样。

JwtAuthenticationProvider 是一个 AuthenticationProvider 实现，它利用 JwtDecoder 和 JwtAuthenticationConverter 来验证 JWT。

我们来看看 JwtAuthenticationProvider 在 Spring Security 中是如何工作的。该图解释了来自读取承载令牌的图中的 AuthenticationManager 如何工作的详细信息。

![jwtauthenticationprovider](https://docs.spring.io/spring-security/reference/_images/servlet/oauth2/jwtauthenticationprovider.png)

编号 1 来自读取承载令牌的身份验证过滤器将 BearerTokenAuthenticationToken 传递给由 ProviderManager 实现的 AuthenticationManager。

编号 2 ProviderManager 配置为使用 JwtAuthenticationProvider 类型的 AuthenticationProvider。

编号 3 JwtAuthenticationProvider 使用 JwtDecoder 解码、验证和验证 Jwt。

数字 4 JwtAuthenticationProvider 然后使用 JwtAuthenticationConverter 将 Jwt 转换为授予权限的集合。

编号 5  身份验证成功时，返回的身份验证属于 JwtAuthenticationToken 类型，并且具有一个主体，该主体是配置的 JwtDecoder 返回的 Jwt。最终，返回的 JwtAuthenticationToken 将由身份验证过滤器在 SecurityContextHolder 上设置。

#### 通过jwk-set-uri 指定授权服务器

如果授权服务器不支持任何配置端点，或者如果资源服务器必须能够独立于授权服务器启动，那么也可以提供 jwk-set-uri：

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://idp.example.com
          jwk-set-uri: https://idp.example.com/.well-known/jwks.json
```

JWK 设置 uri 未标准化，但通常可以在授权服务器的文档中找到
因此，资源服务器不会在启动时 ping 授权服务器。我们仍然指定 issuer-uri，以便资源服务器仍然验证传入 JWT 的 iss 声明。

此属性也可以直接在 DSL 上提供Spring Boot 代表 Resource Server 生成了两个 @Beans。

第一个是 WebSecurityConfigurerAdapter，它将应用程序配置为资源服务器。当包含 spring-security-oauth2-jose 时，这个 WebSecurityConfigurerAdapter 看起来像：

例1 . 默认的JWT配置

```java
protected void configure(HttpSecurity http) {
    http
        .authorizeHttpRequests(authorize -> authorize
            .anyRequest().authenticated()
        )
        .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
}
```

如果应用程序没有公开 WebSecurityConfigurerAdapter bean，那么 Spring Boot 将公开上述默认值。

替换它就像在应用程序中公开 bean 一样简单：

例2 自定义JWT 配置

```java
@EnableWebSecurity
public class MyCustomSecurityConfiguration extends WebSecurityConfigurerAdapter {
    protected void configure(HttpSecurity http) {
        http
            .authorizeHttpRequests(authorize -> authorize
                .mvcMatchers("/messages/**").hasAuthority("SCOPE_message:read")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(myConverter())
                )
            );
    }
}
```

以上要求对以 /messages/ 开头的任何 URL 的 message:read 范围。

oauth2ResourceServer DSL 上的方法也将覆盖或替换自动配置。

例如，@Bean Spring Boot 创建的第二个是 JwtDecoder，它将字符串标记解码为 Jwt 的验证实例：

例3 JWT Decoder 

```java
@Bean
public JwtDecoder jwtDecoder() {
    return JwtDecoders.fromIssuerLocation(issuerUri);
}
```

调用 JwtDecoders#fromIssuerLocation 是调用提供者配置或授权服务器元数据端点以派生 JWK Set Uri 的方法。
如果应用程序没有公开 JwtDecoder bean，那么 Spring Boot 将公开上述默认的 bean。

它的配置可以使用 jwkSetUri() 覆盖或使用decoder() 替换。

或者，如果您根本不使用 Spring Boot，则可以在 XML 中指定这两个组件 - 过滤器链和 JwtDecoder。

过滤器链是这样指定的：

```xml
<http>
    <intercept-uri pattern="/**" access="authenticated"/>
    <oauth2-resource-server>
        <jwt decoder-ref="jwtDecoder"/>
    </oauth2-resource-server>
</http>
```

而 JwtDecoder 就像这样：

示例 5. JWT 解码器

```xml
<bean id="jwtDecoder"
        class="org.springframework.security.oauth2.jwt.JwtDecoders"
        factory-method="fromIssuerLocation">
    <constructor-arg value="${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}"/>
</bean>
```

#### 覆盖或是替换Boot提供的自动配置

##### 使用jwkSetUri()

##### 使用decoder JwtDecoder @Bean



暴露一个

#### 配置可靠的算法

#### 信任单个非对称密钥

#### 信任单个对称密钥

#### 配置授权

#### 配置验证

#### 配置声明集映射

#### 配置超时时间

## 

