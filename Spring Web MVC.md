# Spring Web MVC

## DispatcherServlet

`Spring MVC` 与许多其他 Web 框架一样，围绕前端控制器模式设计，围绕 `Servlet`这个核心，`DispatcherServlet` 提供用于请求处理的共享算法，而实际工作由可配置的委托组件执行。这个模型很灵活，支持不同的工作流程。

![img](http://www.corej2eepatterns.com/images/FCMainClass.gif)

`DispatcherServlet` 与任何 `Servlet` 一样，需要使用 Java 配置或在 web.xml 中根据 Servlet 规范进行声明和映射。反过来，`DispatcherServlet` 使用 Spring 配置来发现请求映射、视图解析、异常处理等所需的委托组件。

以下 Java 配置示例注册并初始化了 `DispatcherServlet`，它由` Servlet` 容器自动检测：

```java
public class MyWebApplicationInitializer implements WebApplicationInitializer {

    @Override
    public void onStartup(ServletContext servletContext) {

        // Load Spring web application configuration
        AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
        context.register(AppConfig.class);

        // Create and register the DispatcherServlet
        DispatcherServlet servlet = new DispatcherServlet(context);
        ServletRegistration.Dynamic registration = servletContext.addServlet("app", servlet);
        registration.setLoadOnStartup(1);
        registration.addMapping("/app/*");
    }
}
```

除了直接使用 `ServletContext API` 之外，还可以扩展` AbstractAnnotationConfigDispatcherServletInitializer `并覆盖特定的方法

```xml
<web-app>

    <listener>
        <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
    </listener>

    <context-param>
        <param-name>contextConfigLocation</param-name>
        <param-value>/WEB-INF/app-context.xml</param-value>
    </context-param>

    <servlet>
        <servlet-name>app</servlet-name>
        <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
        <init-param>
            <param-name>contextConfigLocation</param-name>
            <param-value></param-value>
        </init-param>
        <load-on-startup>1</load-on-startup>
    </servlet>

    <servlet-mapping>
        <servlet-name>app</servlet-name>
        <url-pattern>/app/*</url-pattern>
    </servlet-mapping>

</web-app>
```

Spring Boot 遵循不同的初始化顺序。 Spring Boot 没有挂钩到 Servlet 容器的生命周期，而是使用 Spring 配置来引导自身和嵌入式 Servlet 容器。过滤器和 Servlet 声明在 Spring 配置中检测并注册到 Servlet 容器。

### 上下文层级结构

DispatcherServlet 需要一个 WebApplicationContext（一个普通 ApplicationContext 的扩展）作为它自己的配置。 WebApplicationContext 有一个链接到 ServletContext 和与之关联的 Servlet。它还绑定到 ServletContext 以便应用程序可以使用 RequestContextUtils 上的静态方法来查找 WebApplicationContext，如果他们需要访问它。

对于许多应用程序来说，拥有一个 WebApplicationContext 很简单也足够了。也可以有一个上下文层次结构，其中一个根 WebApplicationContext 在多个 DispatcherServlet（或其他 Servlet）实例之间共享，每个实例都有自己的子 WebApplicationContext 配置。有关上下文层次结构功能的更多信息，请参阅 [ApplicationContext 的附加功能](https://docs.spring.io/spring-framework/docs/current/reference/html/core.html#context-introduction)。

根 WebApplicationContext 通常包含基础架构 bean，例如需要在多个 Servlet 实例之间共享的数据存储库和业务服务。这些 bean 被有效地继承并且可以在特定于 Servlet 的子 WebApplicationContext 中被覆盖（即重新声明），它通常包含给定 Servlet 的本地 bean。下图显示了这种关系：

![mvc context hierarchy](https://docs.spring.io/spring-framework/docs/current/reference/html/images/mvc-context-hierarchy.png)

以下示例配置 WebApplicationContext 层次结构：

```java
public class MyWebAppInitializer extends AbstractAnnotationConfigDispatcherServletInitializer {

    @Override
    protected Class<?>[] getRootConfigClasses() {
        return new Class<?>[] { RootConfig.class };
    }

    @Override
    protected Class<?>[] getServletConfigClasses() {
        return new Class<?>[] { App1Config.class };
    }

    @Override
    protected String[] getServletMappings() {
        return new String[] { "/app1/*" };
    }
}
```

如果不需要应用程序上下文层次结构，应用程序可以通过 getRootConfigClasses() 返回所有配置，从 getServletConfigClasses() 返回 null。

以下示例显示了 web.xml 等效项：

```xml
<web-app>

    <listener>
        <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
    </listener>

    <context-param>
        <param-name>contextConfigLocation</param-name>
        <param-value>/WEB-INF/root-context.xml</param-value>
    </context-param>

    <servlet>
        <servlet-name>app1</servlet-name>
        <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
        <init-param>
            <param-name>contextConfigLocation</param-name>
            <param-value>/WEB-INF/app1-context.xml</param-value>
        </init-param>
        <load-on-startup>1</load-on-startup>
    </servlet>

    <servlet-mapping>
        <servlet-name>app1</servlet-name>
        <url-pattern>/app1/*</url-pattern>
    </servlet-mapping>

</web-app>
```

如果不需要应用程序上下文层次结构，应用程序可以仅配置“根”上下文，并将 contextConfigLocation Servlet 参数留空。

### 特定的Bean类型

DispatcherServlet 委托特定的 bean 来处理请求并呈现适当的响应。 “特定 bean”是指实现框架契约的 Spring 管理的 Object 实例。这些通常带有内置合约，但您可以自定义它们的属性并扩展或替换它们。

下表列出了 DispatcherServlet 检测到的特定 bean：

| Bean 类型                                                    | 解释                                                         |
| :----------------------------------------------------------- | :----------------------------------------------------------- |
| `HandlerMapping`                                             | 将请求与用于预处理和后处理的拦截器列表一起映射到处理程序。映射基于某些标准，其细节因 HandlerMapping 实现而异。两个主要的 HandlerMapping 实现是 RequestMappingHandlerMapping（它支持 @RequestMapping 注释方法）和 SimpleUrlHandlerMapping（它维护 URI 路径模式到处理程序的显式注册）。 |
| `HandlerAdapter`                                             | 帮助 DispatcherServlet 调用映射到请求的处理程序，而不管处理程序实际是如何调用的。例如，调用带注释的控制器需要解析注释。 HandlerAdapter 的主要目的是将 DispatcherServlet 从这些细节中屏蔽掉。 |
| [`HandlerExceptionResolver`](https://docs.spring.io/spring-framework/docs/current/reference/html/web.html#mvc-exceptionhandlers) | 解决异常的策略，可能将它们映射到处理程序、HTML 错误视图或其他目标。 |
| [`ViewResolver`](https://docs.spring.io/spring-framework/docs/current/reference/html/web.html#mvc-viewresolver) | 将从处理程序返回的基于`String` 的逻辑视图名称解析为实际的`View`，用于呈现给响应。参见[视图分辨率](https://docs.spring.io/spring-framework/docs/current/reference/html/web.html#mvc-viewresolver)和[视图技术](https://docs.spring. io/spring-framework/docs/current/reference/html/web.html#mvc-view）。 |
| [`LocaleResolver`](https://docs.spring.io/spring-framework/docs/current/reference/html/web.html#mvc-localeresolver), [LocaleContextResolver](https://docs.spring.io/spring-framework/docs/current/reference/html/web.html#mvc-timezone) | 解析客户端正在使用的“Locale”以及可能的时区，以便能够提供国际化的视图。 |
| [`ThemeResolver`](https://docs.spring.io/spring-framework/docs/current/reference/html/web.html#mvc-themeresolver) | 解决您的 Web 应用程序可以使用的主题 ，例如，提供个性化布局。 |
| [`MultipartResolver`](https://docs.spring.io/spring-framework/docs/current/reference/html/web.html#mvc-multipart) | 在一些多部分解析库的帮助下解析multi-part 请求（例如，浏览器表单文件上传）的抽象。 |
| [`FlashMapManager`](https://docs.spring.io/spring-framework/docs/current/reference/html/web.html#mvc-flash-attributes) | 存储和检索“输入”和“输出”FlashMap，可用于将属性从一个请求传递到另一个请求，通常是通过重定向。请参阅 Flash 属性。 |

### Web MVC 配置

应用程序可以声明在处理请求所需的特殊 Bean 类型中列出的基础设施 Bean。 DispatcherServlet 检查每个特殊 bean 的 WebApplicationContext。如果没有匹配的 bean 类型，它会使用 DispatcherServlet.properties 中列出的默认类型。

在大多数情况下，MVC 配置是最好的起点。它在 Java 或 XML 中声明了所需的 bean，并提供了一个更高级别的配置回调 API 来自定义它。

Spring Boot 依赖 MVC Java 配置来配置 Spring MVC，并提供了许多额外方便的选项。

### Servlet 配置

在 Servlet 3.0+ 环境中，您可以选择以编程方式配置 Servlet 容器作为替代方案或与 web.xml 文件结合使用。以下示例注册一个 DispatcherServlet：

```java
import org.springframework.web.WebApplicationInitializer;

public class MyWebApplicationInitializer implements WebApplicationInitializer {

    @Override
    public void onStartup(ServletContext container) {
        XmlWebApplicationContext appContext = new XmlWebApplicationContext();
        appContext.setConfigLocation("/WEB-INF/spring/dispatcher-config.xml");

        ServletRegistration.Dynamic registration = container.addServlet("dispatcher", new DispatcherServlet(appContext));
        registration.setLoadOnStartup(1);
        registration.addMapping("/");
    }
}
```

WebApplicationInitializer 是 Spring MVC 提供的一个接口，可确保检测到您的实现并自动用于初始化任何 Servlet 3 容器。 WebApplicationInitializer 的抽象基类实现名为 AbstractDispatcherServletInitializer，通过覆盖方法来指定 servlet 映射和 DispatcherServlet 配置的位置，使得注册 DispatcherServlet 变得更加容易。

推荐用于使用基于 Java 的 Spring 配置的应用程序，如以下示例所示：

```
public class MyWebAppInitializer extends AbstractAnnotationConfigDispatcherServletInitializer {

    @Override
    protected Class<?>[] getRootConfigClasses() {
        return null;
    }

    @Override
    protected Class<?>[] getServletConfigClasses() {
        return new Class<?>[] { MyWebConfig.class };
    }

    @Override
    protected String[] getServletMappings() {
        return new String[] { "/" };
    }
}
```

如果使用基于 XML 的 Spring 配置，则应直接从 AbstractDispatcherServletInitializer 扩展，如下例所示：

```java
public class MyWebAppInitializer extends AbstractDispatcherServletInitializer {

    @Override
    protected WebApplicationContext createRootApplicationContext() {
        return null;
    }

    @Override
    protected WebApplicationContext createServletApplicationContext() {
        XmlWebApplicationContext cxt = new XmlWebApplicationContext();
        cxt.setConfigLocation("/WEB-INF/spring/dispatcher-config.xml");
        return cxt;
    }

    @Override
    protected String[] getServletMappings() {
        return new String[] { "/" };
    }
}
```

AbstractDispatcherServletInitializer 还提供了一种方便的方法来添加 Filter 实例并使它们自动映射到 DispatcherServlet，如以下示例所示：

```
public class MyWebAppInitializer extends AbstractDispatcherServletInitializer {

    // ...

    @Override
    protected Filter[] getServletFilters() {
        return new Filter[] {
            new HiddenHttpMethodFilter(), new CharacterEncodingFilter() };
    }
}
```

每个过滤器都根据其具体类型添加了一个默认名称，并自动映射到 DispatcherServlet。

AbstractDispatcherServletInitializer 的 isAsyncSupported 受保护方法提供了一个单一的地方来启用对 DispatcherServlet 和映射到它的所有过滤器的异步支持。默认情况下，此标志设置为 true。

最后，如果您需要进一步自定义 DispatcherServlet 本身，您可以覆盖 createDispatcherServlet 方法。

### 处理

DispatcherServlet 处理请求如下：

* 在请求中搜索并绑定 WebApplicationContext 作为控制器和流程中的其他元素可以使用的属性。它默认绑定在 DispatcherServlet.WEB_APPLICATION_CONTEXT_ATTRIBUTE 键下。

* 语言环境解析器绑定到请求，让进程中的元素在处理请求（呈现视图、准备数据等）时解析要使用的语言环境。如果不需要区域设置解析，则不需要区域设置解析器。

* 主题解析器与请求绑定，让视图等元素决定使用哪个主题。如果您不使用主题，则可以忽略它。

* 如果您指定多部分文件解析器，则会检查请求的多部分。如果找到 multiparts，则请求被包装在 MultipartHttpServletRequest 中，以供流程中的其他元素进一步处理。有关多部分处理的更多信息，请参阅多部分解析器。

* 搜索适当的处理程序。如果找到处理程序，则运行与处理程序关联的执行链（预处理器、后处理器和控制器）以准备用于渲染的模型。或者，对于带注释的控制器，可以呈现响应（在 HandlerAdapter 内）而不是返回视图。

* 如果返回模型，则呈现视图。如果没有返回模型（可能是由于预处理器或后处理器拦截了请求，可能是出于安全原因），则不会呈现视图，因为请求可能已经被满足。

WebApplicationContext 中声明的HandlerExceptionResolver bean 用于解决请求处理过程中抛出的异常。这些异常解析器允许自定义逻辑来解决异常。有关更多详细信息，请参阅例外。

对于 HTTP 缓存支持，处理程序可以使用 WebRequest 的 checkNotModified 方法，以及用于控制器的 HTTP 缓存中所述的注释控制器的更多选项。

您可以通过将 Servlet 初始化参数（init-param 元素）添加到 web.xml 文件中的 Servlet 声明来自定义各个 DispatcherServlet 实例。下表列出了支持的参数：

表1. DispathcherServlet 初始化参数

| 参数                             | 说明                                                         |
| :------------------------------- | :----------------------------------------------------------- |
| `contextClass`                   | 实现 ConfigurableWebApplicationContext 的类，由这个 Servlet 实例化和本地配置。默认情况下，使用 XmlWebApplicationContext。 |
| `contextConfigLocation`          | 传递给上下文实例（由 contextClass 指定）以指示可以找到上下文的位置的字符串。该字符串可能包含多个字符串（使用逗号作为分隔符）以支持多个上下文。在 bean 被定义两次的多个上下文位置的情况下，最新的位置优先。 |
| `namespace`                      | WebApplicationContext 的命名空间。默认为 [servlet-name]-servlet。 |
| `throwExceptionIfNoHandlerFound` | 当没有找到请求的处理程序时是否抛出 NoHandlerFoundException。然后可以使用 HandlerExceptionResolver 捕获异常（例如，通过使用 @ExceptionHandler 控制器方法）并像其他任何方法一样处理。默认情况下，这被设置为 false，在这种情况下 DispatcherServlet 将响应状态设置为 404 (NOT_FOUND) 而不会引发异常。请注意，如果还配置了默认 servlet 处理，则未解析的请求始终转发到默认 servlet，并且永远不会引发 404。 |

### 路径匹配

Servlet API 将完整的请求路径公开为 requestURI，并进一步将其细分为 contextPath、servletPath 和 pathInfo，其值根据 Servlet 的映射方式而有所不同。根据这些输入，Spring MVC 需要确定用于处理程序映射的查找路径，它是 DispatcherServlet 本身的映射中的路径，不包括 contextPath 和任何 servletMapping 前缀（如果存在）。

servletPath 和 pathInfo 被解码，这使得它们无法直接与完整的 requestURI 进行比较以派生 lookupPath 并且需要对 requestURI 进行解码。然而，这引入了它自己的问题，因为路径可能包含编码的保留字符，例如“/”或“;”这反过来会在解码后改变路径的结构，这也会导致安全问题。此外，Servlet 容器可能会在不同程度上对 servletPath 进行规范化，这使得进一步无法针对 requestURI 执行 startsWith 比较。

这就是为什么最好避免依赖基于前缀的 servletPath 映射类型附带的 servletPath。如果 DispatcherServlet 被映射为带有“/”或没有前缀“/*”的默认 Servlet 并且 Servlet 容器是 4.0+，那么 Spring MVC 能够检测到 Servlet 映射类型并完全避免使用 servletPath 和 pathInfo .在 3.1 Servlet 容器上，假设相同的 Servlet 映射类型，可以通过在 MVC 配置中通过路径匹配提供具有 alwaysUseFullPath=true 的 UrlPathHelper 来实现等效。

幸运的是，默认的 Servlet 映射“/”是一个不错的选择。但是，仍然存在一个问题，即需要对 requestURI 进行解码才能与控制器映射进行比较。这又是不可取的，因为有可能对改变路径结构的保留字符进行解码。如果不需要这样的字符，那么您可以拒绝它们（如 Spring Security HTTP 防火墙），或者您可以使用 urlDecode=false 配置 UrlPathHelper，但控制器映射需要与编码路径匹配，这可能并不总是有效。此外，有时 DispatcherServlet 需要与另一个 Servlet 共享 URL 空间，并且可能需要通过前缀映射。

通过从 PathMatcher 切换到 5.3 或更高版本中可用的已解析 PathPattern，可以更全面地解决上述问题，请参阅模式比较。与需要解码查找路径或编码控制器映射的 AntPathMatcher 不同，解析的 PathPattern 与称为 RequestPath 的路径的解析表示匹配，一次一个路径段。这允许单独解码和清理路径段值，而没有改变路径结构的风险。 Parsed PathPattern 也支持使用 servletPath 前缀映射，只要前缀保持简单并且没有任何需要编码的字符。

### 拦截器

所有 HandlerMapping 实现都支持处理程序拦截器，当您希望将特定功能应用于某些请求 — ，例如，检查主体时，这些处理程序拦截器非常有用。拦截器必须从 org.springframework.web.servlet 包中实现 HandlerInterceptor 和三个方法，这些方法应该提供足够的灵活性来进行各种预处理和后处理：

* preHandle(..)：在实际处理程序运行之前

* postHandle(..): 处理程序运行后

* afterCompletion(..): 完整请求完成后

preHandle(..) 方法返回一个布尔值。您可以使用此方法中断或继续执行链的处理。当此方法返回 true 时，处理程序执行链继续。当它返回 false 时，DispatcherServlet 假定拦截器本身已经处理了请求（并且，例如，呈现了一个适当的视图）并且不会继续执行其他拦截器和执行链中的实际处理程序。

有关如何配置拦截器的示例，请参阅 MVC 配置部分中的拦截器。您还可以通过在各个 HandlerMapping 实现上使用 setter 来直接注册它们。

请注意，postHandle 对于 @ResponseBody 和 ResponseEntity 方法的用处不大，在这些方法中，响应是在 HandlerAdapter 内和 postHandle 之前写入和提交的。这意味着对响应进行任何更改（例如添加额外的标头）为时已晚。对于此类场景，您可以实现 ResponseBodyAdvice 并将其声明为 Controller Advice bean 或直接在 RequestMappingHandlerAdapter 上进行配置。

### 异常

如果在请求映射期间发生异常或从请求处理程序（例如@Controller）抛出异常，则 DispatcherServlet 将委托给 HandlerExceptionResolver bean 链来解决异常并提供替代处理，这通常是错误响应。

下表列出了可用的 HandlerExceptionResolver 实现：

表2 HandlerExceptionResolver 实现

| `HandlerExceptionResolver`                                   | 描述                                                         |
| :----------------------------------------------------------- | :----------------------------------------------------------- |
| `SimpleMappingExceptionResolver`                             | 异常类名称和错误视图名称之间的映射。用于在浏览器应用程序中呈现错误页面。 |
| [`DefaultHandlerExceptionResolver`](https://docs.spring.io/spring-framework/docs/5.3.14/javadoc-api/org/springframework/web/servlet/mvc/support/DefaultHandlerExceptionResolver.html) | 解决 Spring MVC 引发的异常并将它们映射到 HTTP 状态代码。另请参阅替代 ResponseEntityExceptionHandler 和 REST API 异常。 |
| `ResponseStatusExceptionResolver`                            | 使用@ResponseStatus 注释解决异常，并根据注释中的值将它们映射到 HTTP 状态代码。 |
| `ExceptionHandlerExceptionResolver`                          | 通过调用@Controller 或@ControllerAdvice 类中的@ExceptionHandler 方法来解决异常。请参阅@ExceptionHandler 方法。 |

### 解析器链

你可以通过在 Spring 配置中声明多个 HandlerExceptionResolver bean 并根据需要设置它们的 order 属性来形成异常解析器链。 order 属性越高，异常解析器定位得越晚。

HandlerExceptionResolver 的契约规定它可以返回：

* 指向错误视图的 ModelAndView。

* 如果在解析器中处理了异常，则为空的 ModelAndView。

* 如果异常仍未解决，则返回 null，供后续解析器尝试，如果异常仍然存在，则允许冒泡到 Servlet 容器。

MVC 配置自动为默认的 Spring MVC 异常、@ResponseStatus 注释异常和@ExceptionHandler 方法的支持声明内置解析器。您可以自定义该列表或替换它。

### 容器错误页面

如果任何 HandlerExceptionResolver 仍未解决异常并因此而继续传播，或者如果响应状态设置为错误状态（即 4xx、5xx），则 Servlet 容器可以在 HTML 中呈现默认错误页面。要自定义容器的默认错误页面，可以在 web.xml 中声明错误页面映射。以下示例显示了如何执行此操作：

```xml
<error-page>
    <location>/error</location>
</error-page>
```

给定前面的示例，当异常冒泡或响应具有错误状态时，Servlet 容器会在容器内将 ERROR 分派到配置的 URL（例如，/error）。然后由 DispatcherServlet 处理，可能将其映射到 @Controller，可以实现它以返回带有模型的错误视图名称或呈现 JSON 响应，如以下示例所示：

```java
@RestController
public class ErrorController {

    @RequestMapping(path = "/error")
    public Map<String, Object> handle(HttpServletRequest request) {
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("status", request.getAttribute("javax.servlet.error.status_code"));
        map.put("reason", request.getAttribute("javax.servlet.error.message"));
        return map;
    }
}
```

Servlet API 不提供在 Java 中创建错误页面映射的方法。但是，您可以同时使用 WebApplicationInitializer 和最小的 web.xml。

### 页面解析

Spring MVC 定义了 ViewResolver 和 View 接口，使您可以在浏览器中呈现模型，而无需将您绑定到特定的视图技术。 ViewResolver 提供了视图名称和实际视图之间的映射。视图解决了在将数据移交给特定视图技术之前的准备工作。

下表提供了有关 ViewResolver 层次结构的更多详细信息：

表3 视图解析器实现

| ViewResolver                     | Description                                                  |
| :------------------------------- | :----------------------------------------------------------- |
| `AbstractCachingViewResolver`    | AbstractCachingViewResolver 的子类缓存它们解析的视图实例。缓存提高了某些视图技术的性能。您可以通过将缓存属性设置为 false 来关闭缓存。此外，如果您必须在运行时刷新某个视图（例如，当修改 FreeMarker 模板时），您可以使用 removeFromCache(String viewName, Locale loc) 方法。 |
| `UrlBasedViewResolver`           | ViewResolver 接口的简单实现，无需显式映射定义即可将逻辑视图名称直接解析为 URL。如果您的逻辑名称以直接的方式与视图资源的名称匹配，而无需任意映射，则这是合适的。 |
| `InternalResourceViewResolver`   | UrlBasedViewResolver 的便捷子类，支持 InternalResourceView（实际上是 Servlet 和 JSP）和子类，例如 JstlView 和 TilesView。您可以使用 setViewClass(..) 为该解析器生成的所有视图指定视图类。有关详细信息，请参阅 UrlBasedViewResolver javadoc。 |
| `FreeMarkerViewResolver`         | UrlBasedViewResolver 的便捷子类，支持 FreeMarkerView 及其自定义子类。 |
| `ContentNegotiatingViewResolver` | ViewResolver 接口的实现，它根据请求文件名或 Accept 标头解析视图。请参阅内容协商。 |
| `BeanNameViewResolver`           | ViewResolver 接口的实现，它将视图名称解释为当前应用程序上下文中的 bean 名称。这是一个非常灵活的变体，它允许基于不同的视图名称混合和匹配不同的视图类型。每个这样的视图都可以定义为一个 bean，例如在 XML 或配置类中。 |

#### 处理

您可以通过声明多个解析器 bean 来链接视图解析器，并在必要时通过设置 order 属性来指定排序。请记住， order 属性越高，视图解析器在链中的位置就越晚。

ViewResolver 的契约指定它可以返回 null 以指示无法找到视图。但是，在 JSP 和 InternalResourceViewResolver 的情况下，确定 JSP 是否存在的唯一方法是通过 RequestDispatcher 执行分派。因此，您必须始终将 InternalResourceViewResolver 配置为在视图解析器的整体顺序中排在最后。

配置视图解析就像将 ViewResolver bean 添加到 Spring 配置一样简单。 MVC 配置为视图解析器和添加无逻辑视图控制器提供了专用的配置 API，这对于没有控制器逻辑的 HTML 模板渲染很有用。

#### 重定向

视图名称中的特殊 redirect: 前缀可让您执行重定向。 UrlBasedViewResolver（及其子类）将此识别为需要重定向的指令。视图名称的其余部分是重定向 URL。

最终效果与控制器返回 RedirectView 相同，但现在控制器本身可以根据逻辑视图名称进行操作。逻辑视图名称（例如重定向：/myapp/some/resource）相对于当前 Servlet 上下文重定向，而名称（例如 redirect:https://myhost.com/some/arbitrary/path）重定向到绝对 URL。

请注意，如果控制器方法使用@ResponseStatus 进行注释，则注释值优先于 RedirectView 设置的响应状态。

#### 转发

您还可以对最终由 UrlBasedViewResolver 和子类解析的视图名称使用特殊的 forward: 前缀。这将创建一个 InternalResourceView，它执行 RequestDispatcher.forward()。因此，这个前缀对于 InternalResourceViewResolver 和 InternalResourceView（对于 JSP）没有用，但是如果您使用另一种视图技术但仍然希望强制转发由 Servlet/JSP 引擎处理的资源，它会很有帮助。请注意，您也可以链接多个视图解析器。

#### 内容协商

ContentNegotiatingViewResolver 本身并不解析视图，而是委托给其他视图解析器并选择与客户端请求的表示相似的视图。可以根据 Accept 标头或查询参数（例如，“/path?format=pdf”）确定表示形式。

ContentNegotiatingViewResolver 通过将请求媒体类型与与每个 ViewResolver 关联的 View 支持的媒体类型（也称为 Content-Type）进行比较来选择合适的 View 来处理请求。列表中第一个具有兼容 Content-Type 的 View 将表示返回给客户端。如果 ViewResolver 链无法提供兼容的视图，则会查询通过 DefaultViews 属性指定的视图列表。后一个选项适用于可以呈现当前资源的适当表示的单例视图，而不管逻辑视图名称如何。 Accept 标头可以包含通配符（例如 text/*），在这种情况下，Content-Type 为 text/xml 的视图是兼容匹配项。

有关配置详细信息，请参阅 MVC 配置下的查看解析器。

### 语言环境

Spring 架构的大部分都支持国际化，就像 Spring Web MVC 框架一样。 DispatcherServlet 允许您使用客户端的语言环境自动解析消息。这是通过 LocaleResolver 对象完成的。

当一个请求进来时，DispatcherServlet 会寻找一个区域设置解析器，如果找到了，它会尝试使用它来设置区域设置。通过使用 RequestContext.getLocale() 方法，您始终可以检索由区域设置解析器解析的区域设置。

除了自动区域设置解析之外，您还可以将拦截器附加到处理程序映射（有关处理程序映射拦截器的更多信息，请参阅拦截）以在特定情况下更改区域设置（例如，基于请求中的参数）。

语言环境解析器和拦截器在 org.springframework.web.servlet.i18n 包中定义，并以正常方式在您的应用程序上下文中配置。 Spring 中包含以下选择的区域设置解析器。

#### 时区

除了获取客户端的语言环境之外，了解其时区通常也很有用。 LocaleContextResolver 接口提供了 LocaleResolver 的扩展，让解析器提供更丰富的 LocaleContext，其中可能包含时区信息。

可用时，可以使用 RequestContext.getTimeZone() 方法获取用户的 TimeZone。任何注册到 Spring 的 ConversionService 的 Date/Time Converter 和 Formatter 对象都会自动使用时区信息。

#### 请求头解析

此区域设置解析器检查客户端（例如，Web 浏览器）发送的请求中的接受语言标头。通常，此标头字段包含客户端操作系统的区域设置。请注意，此解析器不支持时区信息。

#### Cookie 解析

此区域设置解析器检查客户端上可能存在的 Cookie，以查看是否指定了区域设置或时区。如果是，则使用指定的详细信息。通过使用此区域设置解析器的属性，您可以指定 cookie 的名称以及最长期限。以下示例定义了 CookieLocaleResolver：

```
<bean id="localeResolver" class="org.springframework.web.servlet.i18n.CookieLocaleResolver">

    <property name="cookieName" value="clientlanguage"/>

    <!-- in seconds. If set to -1, the cookie is not persisted (deleted when browser shuts down) -->
    <property name="cookieMaxAge" value="100000"/>

</bean>
```

下表描述了 CookieLocaleResolver 的属性：

表4. Cookie语言环境解析器属性

| Property       | Default                   | Description                                                  |
| :------------- | :------------------------ | :----------------------------------------------------------- |
| `cookieName`   | classname + LOCALE        | cookie名称                                                   |
| `cookieMaxAge` | Servlet container default | cookie 在客户端上保留的最长时间。如果指定了 -1，cookie 将不会被持久化。它仅在客户端关闭浏览器之前可用。 |
| `cookiePath`   | /                         | 将 cookie 的可见性限制在您网站的某个部分。指定 cookiePath 时，cookie 仅对该路径及其下方的路径可见。 |

#### Session 解析

SessionLocaleResolver 允许您从可能与用户请求相关联的会话中检索区域设置和时区。与 CookieLocaleResolver 不同，此策略将本地选择的区域设置存储在 Servlet 容器的 HttpSession 中。因此，这些设置对于每个会话都是临时的，因此在每个会话结束时都会丢失。

请注意，与外部会话管理机制没有直接关系，例如 Spring Session 项目。此 SessionLocaleResolver 根据当前 HttpServletRequest 评估和修改相应的 HttpSession 属性。

#### 语言环境解析器

您可以通过将 LocaleChangeInterceptor 添加到 HandlerMapping 定义之一来启用区域设置的更改。它检测请求中的参数并相应地更改区域设置，在调度程序的应用程序上下文中调用 LocaleResolver 上的 setLocale 方法。下一个示例显示对包含名为 siteLanguage 的参数的所有 *.view 资源的调用现在会更改区域设置。因此，例如，对 URL https://www.sf.net/home.view?siteLanguage=nl 的请求会将站点语言更改为荷兰语。以下示例显示了如何拦截语言环境：

```
<bean id="localeChangeInterceptor"
        class="org.springframework.web.servlet.i18n.LocaleChangeInterceptor">
    <property name="paramName" value="siteLanguage"/>
</bean>

<bean id="localeResolver"
        class="org.springframework.web.servlet.i18n.CookieLocaleResolver"/>

<bean id="urlMapping"
        class="org.springframework.web.servlet.handler.SimpleUrlHandlerMapping">
    <property name="interceptors">
        <list>
            <ref bean="localeChangeInterceptor"/>
        </list>
    </property>
    <property name="mappings">
        <value>/**/*.view=someController</value>
    </property>
</bean>
```

### 主题

您可以应用 Spring Web MVC 框架主题来设置应用程序的整体外观，从而增强用户体验。主题是影响应用程序视觉样式的静态资源的集合，通常是样式表和图像。

#### 定义主题

要在 Web 应用程序中使用主题，您必须设置 org.springframework.ui.context.ThemeSource 接口的实现。 WebApplicationContext 接口扩展了 ThemeSource，但将其职责委托给了一个专门的实现。默认情况下，委托是一个 org.springframework.ui.context.support.ResourceBundleThemeSource 实现，它从类路径的根加载属性文件。要使用自定义 ThemeSource 实现或配置 ResourceBundleThemeSource 的基本名称前缀，您可以在应用程序上下文中使用保留名称 themeSource 注册一个 bean。 Web 应用程序上下文会自动检测具有该名称的 bean 并使用它。

当您使用 ResourceBundleThemeSource 时，会在一个简单的属性文件中定义一个主题。属性文件列出了构成主题的资源，如以下示例所示：

```
styleSheet=/themes/cool/style.css
background=/themes/cool/img/coolBg.jpg
```

属性的键是从视图代码中引用主题元素的名称。对于 JSP，您通常使用 spring:theme 自定义标记来执行此操作，该标记与 spring:message 标记非常相似。以下 JSP 片段使用前面示例中定义的主题来自定义外观：

```xml
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<html>
    <head>
        <link rel="stylesheet" href="<spring:theme code='styleSheet'/>" type="text/css"/>
    </head>
    <body style="background=<spring:theme code='background'/>">
        ...
    </body>
</html>
```

默认情况下，ResourceBundleThemeSource 使用空的基本名称前缀。因此，属性文件是从类路径的根目录加载的。因此，您可以将 cool.properties 主题定义放在类路径根目录下（例如，在 /WEB-INF/classes 中）。 ResourceBundleThemeSource 使用标准的 Java 资源包加载机制，允许主题完全国际化。例如，我们可以有一个 /WEB-INF/classes/cool_nl.properties 来引用带有荷兰语文本的特殊背景图像。

#### 解析主题

定义主题后，如前一节所述，您可以决定使用哪个主题。 DispatcherServlet 查找名为 themeResolver 的 bean 以找出要使用的 ThemeResolver 实现。主题解析器的工作方式与 LocaleResolver 大致相同。它检测用于特定请求的主题，还可以更改请求的主题。下表描述了 Spring 提供的主题解析器：

表5 主题解析实现

| Class                  | 描述                                                         |
| :--------------------- | :----------------------------------------------------------- |
| `FixedThemeResolver`   | 选择使用 defaultThemeName 属性设置的固定主题。               |
| `SessionThemeResolver` | 主题在用户的 HTTP 会话中维护。它只需要为每个会话设置一次，但不会在会话之间持久化。 |
| `CookieThemeResolver`  | 所选主题存储在客户端的 cookie 中。                           |

Spring 还提供了一个 ThemeChangeInterceptor，它允许使用简单的请求参数在每个请求上更改主题。

### Multipart 解析器

来自 org.springframework.web.multipart 包的 MultipartResolver 是一种用于解析包括文件上传在内的多部分请求的策略。有一种基于 Commons FileUpload 的实现，另一种基于 Servlet 3.0 多部分请求解析。

要启用多部分处理，您需要在 DispatcherServlet Spring 配置中声明一个名为 multipartResolver 的 MultipartResolver bean。 DispatcherServlet 检测到它并将其应用于传入的请求。当接收到内容类型为 multipart/form-data 的 POST 时，解析器解析内容，将当前 HttpServletRequest 包装为 MultipartHttpServletRequest 以提供对解析文件的访问，以及将部分公开为请求参数。

#### Apache Commons FileUplod

要使用 Apache Commons FileUpload，您可以配置一个名为 multipartResolver 的 CommonsMultipartResolver 类型的 bean。您还需要将 commons-fileupload jar 作为类路径的依赖项。

这个解析器变体委托给应用程序中的本地库，提供跨 Servlet 容器的最大可移植性。作为替代方案，可以考虑通过容器自己的解析器进行标准的 Servlet 多部分解析，如下所述。

Commons FileUpload 传统上仅适用于 POST 请求，但接受任何多部分/内容类型。有关详细信息和配置选项，请参阅 CommonsMultipartResolver javadoc。

#### Servlet 3.0

Servlet 3.0 多部分解析需要通过 Servlet 容器配置开启。这样做：

在 Java 中，在 Servlet 注册上设置 MultipartConfigElement。

在 web.xml 中，将“<multipart-config>”部分添加到 servlet 声明。

以下示例显示如何在 Servlet 注册上设置 MultipartConfigElement：

```java
public class AppInitializer extends AbstractAnnotationConfigDispatcherServletInitializer {

    // ...

    @Override
    protected void customizeRegistration(ServletRegistration.Dynamic registration) {

        // Optionally also set maxFileSize, maxRequestSize, fileSizeThreshold
        registration.setMultipartConfig(new MultipartConfigElement("/tmp"));
    }

}
```

一旦 Servlet 3.0 配置就位，您可以添加一个名称为 multipartResolver 的 StandardServletMultipartResolver 类型的 bean。

此解析器变体按原样使用 Servlet 容器的多部分解析器，可能会将应用程序暴露于容器实现差异。默认情况下，它会尝试使用任何 HTTP 方法解析任何多部分/内容类型，但这可能不受所有 Servlet 容器的支持。有关详细信息和配置选项，请参阅 StandardServletMultipartResolver javadoc。

### 日志记录

Spring MVC 中的 DEBUG 级日志被设计为紧凑、最小化和人性化。它侧重于反复有用的高价值信息，而不是仅在调试特定问题时有用的其他信息。

TRACE 级别的日志记录通常遵循与 DEBUG 相同的原则（例如，也不应该是消防水带），但可用于调试任何问题。此外，某些日志消息可能会在 TRACE 与 DEBUG 中显示不同级别的详细信息。

良好的日志记录来自使用日志的经验。如果您发现任何不符合既定目标的内容，请告诉我们。

#### 敏感数据

DEBUG 和 TRACE 日志记录可能会记录敏感信息。这就是为什么请求参数和标头在默认情况下被屏蔽，并且必须通过 DispatcherServlet 上的 enableLoggingRequestDetails 属性显式启用它们的完整日志记录。

以下示例显示了如何使用 Java 配置执行此操作：

```java
public class MyInitializer
        extends AbstractAnnotationConfigDispatcherServletInitializer {

    @Override
    protected Class<?>[] getRootConfigClasses() {
        return ... ;
    }

    @Override
    protected Class<?>[] getServletConfigClasses() {
        return ... ;
    }

    @Override
    protected String[] getServletMappings() {
        return ... ;
    }

    @Override
    protected void customizeRegistration(ServletRegistration.Dynamic registration) {
        registration.setInitParameter("enableLoggingRequestDetails", "true");
    }

}
```

