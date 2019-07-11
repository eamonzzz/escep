package com.eamon.escep.controller;

import com.eamon.escep.service.ScepService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author: eamon
 * @date: 2019-07-11 11:14
 * @description:
 */
@RestController
@RequestMapping("/scep")
public class ScepController {

    @Autowired
    ScepService scepService;

    @RequestMapping("/pkiclient.exe")
    public void requestScep(HttpServletRequest request, HttpServletResponse response) {
        scepService.requestScep(request, response);
    }

}
