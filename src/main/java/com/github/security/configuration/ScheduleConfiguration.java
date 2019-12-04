package com.github.security.configuration;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.github.security.schedule.ClearBlacklistSchedule;

@Configuration
public class ScheduleConfiguration {
	
	@Bean(initMethod = "initSchedule")
	@ConditionalOnMissingBean
	public ClearBlacklistSchedule clearBlacklistSchedule() {
		return new ClearBlacklistSchedule();
	}

}
