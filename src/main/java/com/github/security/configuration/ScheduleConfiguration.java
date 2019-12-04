package com.github.security.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.github.security.schedule.ClearBlacklistSchedule;

@Configuration
public class ScheduleConfiguration {
	
	@Autowired
	private JwtProperties p;
	
	@Bean(initMethod = "initSchedule")
	@ConditionalOnMissingBean
	public ClearBlacklistSchedule clearBlacklistSchedule() {
		ClearBlacklistSchedule schedule = new ClearBlacklistSchedule();
		schedule.setClearInterval(p.getClearInterval());
		return schedule;
	}

}
