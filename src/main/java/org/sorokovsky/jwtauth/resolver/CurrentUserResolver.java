package org.sorokovsky.jwtauth.resolver;

import lombok.RequiredArgsConstructor;
import org.sorokovsky.jwtauth.annotation.CurrentUser;
import org.sorokovsky.jwtauth.model.UserDetailsModel;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

@Component
@RequiredArgsConstructor
public class CurrentUserResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.getParameterAnnotation(CurrentUser.class) != null;
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
        final var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) return null;
        final var user = (UserDetailsModel) authentication.getPrincipal();
        return user.getUser();
    }
}
