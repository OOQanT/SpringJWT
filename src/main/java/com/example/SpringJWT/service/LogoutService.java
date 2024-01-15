package com.example.SpringJWT.service;

import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

//로그아웃 요청으로 오는 토큰을 set에 담음
//set에 담긴 토큰으로 오는 요청은 거부

@Service
public class LogoutService {
    private Set<String> blackList = new HashSet<>();

    public void addToBlackList(String token){
        blackList.add(token);
    }

    public boolean isBlackListed(String token){
        return blackList.contains(token);
    }
}
