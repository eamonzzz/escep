package com.eamon.escep.service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author: eamon
 * @date: 2019-07-11 11:20
 * @description:
 */
public interface ScepService {
    /**
     * scep 请求
     *
     * @param request
     * @param response
     */
    void requestScep(HttpServletRequest request, HttpServletResponse response);

}
