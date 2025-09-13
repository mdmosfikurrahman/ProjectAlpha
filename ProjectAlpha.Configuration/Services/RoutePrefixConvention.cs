using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.AspNetCore.Mvc.Routing;

namespace ProjectAlpha.Configuration.Services;

public sealed class RoutePrefixConvention(IRouteTemplateProvider routeTemplateProvider) : IApplicationModelConvention
{
    private readonly AttributeRouteModel _prefix = new(routeTemplateProvider);

    public void Apply(ApplicationModel application)
    {
        foreach (var controller in application.Controllers)
        {
            foreach (var selector in controller.Selectors)
            {
                if (selector.AttributeRouteModel != null)
                {
                    selector.AttributeRouteModel =
                        AttributeRouteModel.CombineAttributeRouteModel(_prefix, selector.AttributeRouteModel);
                }
            }
        }
    }
}