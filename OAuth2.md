#  OAuth2

Spring Security 提供了完整的OAuth 2支持.这部分内容讲的是如何把OAuth集成到基于Servlet的应用.



## OAuth2 登录

OAuth 2.0 登录特性给应用提供了让用户使用已有账号登录的能力,例如GitHub和Google的账号。OAuth 2.0登录实现的就是

使用Google登录或是使用GitHub登录的用例。

  OAuth 2.0登录是使用授权码模式实现的，正如[OAuth 2.0 授权框架](https://tools.ietf.org/html/rfc6749#section-4.1)以及[OPenID Connect 核心 1.0](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)所说明的那样。

### 核心配置

#### Spring Boot 2.0 样例

Spring Boot 2.x 为OAuth 2.0 登录提供完全的自动配置能力.

这部分内容展示了[OAuth 2.0 登录样例](https://github.com/spring-projects/spring-security-samples/tree/main/servlet/spring-boot/java/oauth2/login)是如何使用Google作为认证服务提供者的.

##### 初始化

##### 设置重定向URI

##### 配置application.yml

##### 启动应用

#### Spring Boot 2.0属性对照表

#### CommonOAuth2Provider

#### 配置自定义提供者属性

#### 覆盖Spring Boot 2.x 自动配置

##### 注册一个ClientRegistrationRepository @Bean

##### 提供一个WebSecurityConfigurerAdapter

##### 完全覆盖自动配置

#### 非Spring Boot 2.x项目的Java配置

````java
@Configuration
public class OAuth2LoginConfig {

	@EnableWebSecurity
	public static class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeHttpRequests(authorize -> authorize
					.anyRequest().authenticated()
				)
				.oauth2Login(withDefaults());
		}
	}

	@Bean
	public ClientRegistrationRepository clientRegistrationRepository() {
		return new InMemoryClientRegistrationRepository(this.googleClientRegistration());
	}

	@Bean
	public OAuth2AuthorizedClientService authorizedClientService(
			ClientRegistrationRepository clientRegistrationRepository) {
		return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
	}

	@Bean
	public OAuth2AuthorizedClientRepository authorizedClientRepository(
			OAuth2AuthorizedClientService authorizedClientService) {
		return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
	}

	private ClientRegistration googleClientRegistration() {
		return CommonOAuth2Provider.GOOGLE.getBuilder("google")
			.clientId("google-client-id")
			.clientSecret("google-client-secret")
			.build();
	}
}
````

### 高级配置

HttpSecurity.oauth2login() 提供了一些自定义OAuth 2.0 登录的配置项.主要的配置选项按照它们协议的端点分成了几个部分.

例如,oauth2Login.authorizationEndpoint()可以对授权端点进行配置,oauth2Login().tokenEndpoint()可以对令牌端点进行配置.

例子如下:

例1. 高级 OAuth2 登录配置

```java
@EnableWebSecurity
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.oauth2Login(oauth2 -> oauth2
			    .authorizationEndpoint(authorization -> authorization
			            ...
			    )
			    .redirectionEndpoint(redirection -> redirection
			            ...
			    )
			    .tokenEndpoint(token -> token
			            ...
			    )
			    .userInfoEndpoint(userInfo -> userInfo
			            ...
			    )
			);
	}
}
```

oauth2Login() DLS 的目标是与说明中的名称保持一致.

OAuth 2.0 授权框架定义了如下的[协议端点](https://tools.ietf.org/html/rfc6749#section-3):

授权过程使用了两个授权服务器端点(HTTP 资源)

* 授权端点:被客户端用来让资源所有者以用户代理重定向获取授权
* 令牌端点:被客户端用来以授权交换令牌,通常是以客户端授权的方式

以及一个客户端端点:

* 重定向端点:被授权服务以资源所有者用户代理用来将包含授权证书的响应返回给客户端.

OpenID Connect  核心 1.0说明定义了如下的用户端点:

用户信息端点是一个被OAuth 2.0所保护的资源,返回的认证过的用户的声明.要获取想要的关于用户的

声明,客户端通过从Open Connect 认证获取的访问令牌对用户信息端点做出请求.这些声明通常是一个包含键值对的

JSON 对象.

以下的代码展示了一个完整可用的oauth2Login() DSL 配置.

例2. OAuth2 登录配置项

```java
@EnableWebSecurity
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.oauth2Login(oauth2 -> oauth2
			    .clientRegistrationRepository(this.clientRegistrationRepository())
			    .authorizedClientRepository(this.authorizedClientRepository())
			    .authorizedClientService(this.authorizedClientService())
			    .loginPage("/login")
			    .authorizationEndpoint(authorization -> authorization
			        .baseUri(this.authorizationRequestBaseUri())
			        .authorizationRequestRepository(this.authorizationRequestRepository())
			        .authorizationRequestResolver(this.authorizationRequestResolver())
			    )
			    .redirectionEndpoint(redirection -> redirection
			        .baseUri(this.authorizationResponseBaseUri())
			    )
			    .tokenEndpoint(token -> token
			        .accessTokenResponseClient(this.accessTokenResponseClient())
			    )
			    .userInfoEndpoint(userInfo -> userInfo
			        .userAuthoritiesMapper(this.userAuthoritiesMapper())
			        .userService(this.oauth2UserService())
			        .oidcUserService(this.oidcUserService())
			    )
			);
	}
}
```

除了 oauth2Login() DSL之外, XML配置也是支持的.

以下的代码展示了security命名空间下的完整的配置项.

例3. OAuth 2 登录 XML 配置项

```xml
<http>
	<oauth2-login client-registration-repository-ref="clientRegistrationRepository"
				  authorized-client-repository-ref="authorizedClientRepository"
				  authorized-client-service-ref="authorizedClientService"
				  authorization-request-repository-ref="authorizationRequestRepository"
				  authorization-request-resolver-ref="authorizationRequestResolver"
				  access-token-response-client-ref="accessTokenResponseClient"
				  user-authorities-mapper-ref="userAuthoritiesMapper"
				  user-service-ref="oauth2UserService"
				  oidc-user-service-ref="oidcUserService"
				  login-processing-url="/login/oauth2/code/*"
				  login-page="/login"
				  authentication-success-handler-ref="authenticationSuccessHandler"
				  authentication-failure-handler-ref="authenticationFailureHandler"
				  jwt-decoder-factory-ref="jwtDecoderFactory"/>
</http>
```

#### OAuth 2.0 登录页面

#### 重定向端点

#### 用户信息端点

#### ID TOKEN 签名认证

#### OpenID Connect 1.0 登出

## OAuth2 客户端

OAuth 2.0客户端特性提供对[OAuth 2.0 授权框架](https://tools.ietf.org/html/rfc6749#section-1.1)所定义的客户端角色的支持.

从高层次看,核心特性如下:

授权支持

* [授权码](https://tools.ietf.org/html/rfc6749#section-1.3.1)
* [刷新令牌](https://tools.ietf.org/html/rfc6749#section-6)
* [客户端凭证](https://tools.ietf.org/html/rfc6749#section-1.3.4)
* [资源所有者密码凭证](https://tools.ietf.org/html/rfc6749#section-1.3.3)
* [JWT Bearer](https://datatracker.ietf.org/doc/html/rfc7523#section-2.1)

客户端认证支持

* [JWT Bearer]([JWT Bearer](https://datatracker.ietf.org/doc/html/rfc7523#section-2.2))

HTTP 客户端支持

* [Servlet环境下的 webClient集成](https://docs.spring.io/spring-security/reference/servlet/oauth2/client/authorized-clients.html#oauth2Client-webclient-servlet)(用于请求被保护的资源)

HTTPSecurity.oauth2Client() DSL 提供了一些 OAuth2.0 客户端所使用的核心组件的配置项.

此外,HttpSecurity.oauth2Client().authorizationCodeGrant()使得授权码认证自定义成为可能.

以下的代码展示了HttpSecurity.oauth2Client() DSL提供的完整配置项

例1. OAuth2 客户端配置项

```java
@EnableWebSecurity
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.oauth2Client(oauth2 -> oauth2
				.clientRegistrationRepository(this.clientRegistrationRepository())
				.authorizedClientRepository(this.authorizedClientRepository())
				.authorizedClientService(this.authorizedClientService())
				.authorizationCodeGrant(codeGrant -> codeGrant
					.authorizationRequestRepository(this.authorizationRequestRepository())
					.authorizationRequestResolver(this.authorizationRequestResolver())
					.accessTokenResponseClient(this.accessTokenResponseClient())
				)
			);
	}
}
```

除了HttpSecurity.oauth2Client() DSL,XML 配置也是支持的.

以下代码展示了security命名空间下完整的配置项:

例2. OAuth2 客户端配置项

```xml
<http>
	<oauth2-client client-registration-repository-ref="clientRegistrationRepository"
				   authorized-client-repository-ref="authorizedClientRepository"
				   authorized-client-service-ref="authorizedClientService">
		<authorization-code-grant
				authorization-request-repository-ref="authorizationRequestRepository"
				authorization-request-resolver-ref="authorizationRequestResolver"
				access-token-response-client-ref="accessTokenResponseClient"/>
	</oauth2-client>
</http>
```

OAuth2AuthorizedClientManager负责管理OAuth 2.0客户端的授权(再授权),是可以与一个或多个

OAuth2AuthorizedClientProvider合作的.

以下的代码展示了如何注册一个OAuth2AuthorizedClientManager@Bean,并将一个提供`authorization_code`, `refresh_token`, `client_credentials` and `password` 授权方式的OAuth2AuthorizedClientProvider组合与之相关联.

```java
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
		ClientRegistrationRepository clientRegistrationRepository,
		OAuth2AuthorizedClientRepository authorizedClientRepository) {

	OAuth2AuthorizedClientProvider authorizedClientProvider =
			OAuth2AuthorizedClientProviderBuilder.builder()
					.authorizationCode()
					.refreshToken()
					.clientCredentials()
					.password()
					.build();

	DefaultOAuth2AuthorizedClientManager authorizedClientManager =
			new DefaultOAuth2AuthorizedClientManager(
					clientRegistrationRepository, authorizedClientRepository);
	authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

	return authorizedClientManager;
}
```

### 核心接口和类

### OAuth2 授权方式

#### ClientRegister

#### ClientRegistrationRepository

#### OAuth2AuthorizedClient

#### OAuth2AuthorizedClientRepository / OAuth2AuthorizedClientService

#### OAuth2AuthorizedClientManager / OAuth2AuthorizedClientProvider

### OAuth2 客户端认证

#### 授权码

#### 刷新令牌

#### 客户端凭证

#### 资源所有者密码凭证

#### JWT Bearer

### OAuth2 已授权客户端

## OAuth2 资源服务器

Spring Security 支持使用以下两种OAuth 2.0 [Bearer 令牌](https://tools.ietf.org/html/rfc6750.html)来保护端点:

* [JWT](https://tools.ietf.org/html/rfc7519)
* 不透明令牌

这在应用把它的授权管理代理给一个授权服务的时候是比较方便的.授权服务器能被资源服务器查询来对请求进行授权.

这部分内容提供了Spring Security如何提供OAuth 2.0 Bearer 令牌支持的细节.

来看下Bearer 令牌是如何在Spring Security中运作的.首先就像Basic认证一样,[WWW-Authenticate](https://tools.ietf.org/html/rfc7235#section-4.1) 请求头会被发送回给客户端.

![bearerauthenticationentrypoint](https://docs.spring.io/spring-security/reference/_images/servlet/oauth2/bearerauthenticationentrypoint.png)



上图展示了所对应的SecurityFilterchain

## OAuth2 授权服务器





