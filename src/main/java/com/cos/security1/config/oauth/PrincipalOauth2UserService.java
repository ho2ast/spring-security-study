package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        // 구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인을 완료 -> code를 리턴(OAuth-Client 라이브러리) -> Access Token 요청
        // userRequest 정보 -> loadUser함수 호출 -> 구글로부터 회원프로필을 받아준다.
        System.out.println("oAuth2User.getAttributes() = " + oAuth2User.getAttributes());

        String provider = userRequest.getClientRegistration().getClientId(); // google
        String providerId = oAuth2User.getAttribute("sub");
        String username = provider + "_" + providerId;
        String password = bCryptPasswordEncoder.encode("getInThere");
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";

        User user = userRepository.findByUsername(username);
        if (user == null) {
            user = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .provideId(providerId)
                    .build();
            userRepository.save(user);
        }

        return new PrincipalDetails(user, oAuth2User.getAttributes());
    }
}
