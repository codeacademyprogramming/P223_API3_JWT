#pragma checksum "C:\Users\Eagha\Desktop\CodeLessons\P223\4. 10-02-2022\ShopApiP223\ShopMvc\Views\Category\Index.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "7a439720573e79f2bd45ce8abed518419a9ce199"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Category_Index), @"mvc.1.0.view", @"/Views/Category/Index.cshtml")]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#nullable restore
#line 1 "C:\Users\Eagha\Desktop\CodeLessons\P223\4. 10-02-2022\ShopApiP223\ShopMvc\Views\_ViewImports.cshtml"
using ShopMvc;

#line default
#line hidden
#nullable disable
#nullable restore
#line 2 "C:\Users\Eagha\Desktop\CodeLessons\P223\4. 10-02-2022\ShopApiP223\ShopMvc\Views\_ViewImports.cshtml"
using ShopMvc.Models;

#line default
#line hidden
#nullable disable
#nullable restore
#line 3 "C:\Users\Eagha\Desktop\CodeLessons\P223\4. 10-02-2022\ShopApiP223\ShopMvc\Views\_ViewImports.cshtml"
using ShopMvc.DTOs;

#line default
#line hidden
#nullable disable
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"7a439720573e79f2bd45ce8abed518419a9ce199", @"/Views/Category/Index.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"831ac015a9f0b4607e3dc4554964c50634f3ed64", @"/Views/_ViewImports.cshtml")]
    public class Views_Category_Index : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<CategoryListDto>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
#nullable restore
#line 2 "C:\Users\Eagha\Desktop\CodeLessons\P223\4. 10-02-2022\ShopApiP223\ShopMvc\Views\Category\Index.cshtml"
  
    ViewData["Title"] = "Index";
    int count = 0;

#line default
#line hidden
#nullable disable
            WriteLiteral(@"
<h1>Categories</h1>

<div class=""container"">
    <div class=""row"">
        <div class=""col-md-8 mx-auto"">
            <table class=""table"">
                <thead>
                    <tr>
                        <th scope=""col"">#</th>
                        <th scope=""col"">Id</th>
                        <th scope=""col"">Name</th>
                    </tr>
                </thead>
                <tbody>

");
#nullable restore
#line 22 "C:\Users\Eagha\Desktop\CodeLessons\P223\4. 10-02-2022\ShopApiP223\ShopMvc\Views\Category\Index.cshtml"
                     foreach (var item in Model.Items)
                    {
                        count++;

#line default
#line hidden
#nullable disable
            WriteLiteral("                        <tr>\r\n                            <th scope=\"row\">");
#nullable restore
#line 26 "C:\Users\Eagha\Desktop\CodeLessons\P223\4. 10-02-2022\ShopApiP223\ShopMvc\Views\Category\Index.cshtml"
                                       Write(count);

#line default
#line hidden
#nullable disable
            WriteLiteral("</th>\r\n                            <td>");
#nullable restore
#line 27 "C:\Users\Eagha\Desktop\CodeLessons\P223\4. 10-02-2022\ShopApiP223\ShopMvc\Views\Category\Index.cshtml"
                           Write(item.Id);

#line default
#line hidden
#nullable disable
            WriteLiteral("</td>\r\n                            <td>");
#nullable restore
#line 28 "C:\Users\Eagha\Desktop\CodeLessons\P223\4. 10-02-2022\ShopApiP223\ShopMvc\Views\Category\Index.cshtml"
                           Write(item.Name);

#line default
#line hidden
#nullable disable
            WriteLiteral("</td>\r\n                        </tr>\r\n");
#nullable restore
#line 30 "C:\Users\Eagha\Desktop\CodeLessons\P223\4. 10-02-2022\ShopApiP223\ShopMvc\Views\Category\Index.cshtml"
                    }

#line default
#line hidden
#nullable disable
            WriteLiteral("                </tbody>\r\n            </table>\r\n\r\n        </div>\r\n    </div>\r\n</div>\r\n");
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<CategoryListDto> Html { get; private set; }
    }
}
#pragma warning restore 1591
