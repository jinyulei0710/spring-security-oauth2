# 架构

本节讨论的是在基于`Servlet`应用中`Spring Security`的高层次架构。要理解这个架构，需要建立认证、授权、以及漏洞防护相关内容的只上。

### 过滤器回顾

Spring Security 的 `Servlet` 支持是基于 `Servlet Filters` 的，所以先大致了解一下 Filters 的作用是有帮助的。下图显示了单个 HTTP 请求的处理程序的典型分层。

![filterchain](https://docs.spring.io/spring-security/reference/_images/servlet/architecture/filterchain.png)

​                                                                                                                  过滤器链

客户端发送一个请求到应用，容器创建了一个包含过滤器和基于请求路径对`HttpServletRequest`进行处理的`Servlet`的`FilterChain`.在`Spring MVC `应用中 `Servlet`是 `DispatchServlet`的一个实例。一个`Servlet`最多能够处理单个`HttpServletRequest `和 `HttpServletResponse`。但是呢，可以使用多个过滤器。

- 阻止下游的过滤器或`Servlet`被调用。在这个实例中，通常会写入到`HttpServletResponse`。
- 修改被下游过滤器或者`Servlet`所使用的`HttpServletRequest` 和 `HttpServletResponse`。

例1.

```java
public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
	// do something before the rest of the application
    chain.doFilter(request, response); // invoke the rest of the application
    // do something after the rest of the application
}
```

因为过滤器只影响它的下游过滤器以及`Servlet`,过滤器调用的顺序就显得格外重要。



## 