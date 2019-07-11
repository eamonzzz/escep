package com.eamon.escep.service.impl;

import com.eamon.escep.exception.ScepServerException;
import com.eamon.escep.server.ScepServer;
import com.eamon.escep.service.ScepService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author: eamon
 * @date: 2019-07-11 11:20
 * @description:
 */
@Service
public class ScepServiceImpl implements ScepService {

    @Autowired
    ScepServer scepServer;

    @Override
    public void requestScep(HttpServletRequest request, HttpServletResponse response) {
        try {
            scepServer.server(request, response);
        } catch (ScepServerException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
