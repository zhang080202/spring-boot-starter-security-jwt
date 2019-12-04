package com.github.security.schedule;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.github.security.utils.CacheManager;

/**
 * 清理黑名单中过期token 10秒执行一次
 * @author zhangyf
 *
 */
public class ClearBlacklistSchedule {
	
	public void initSchedule() {
		clearBlacklist();
	}
	
	public void clearBlacklist() {
		ScheduledExecutorService schedule = Executors.newScheduledThreadPool(2);
		schedule.scheduleAtFixedRate(new ClearSchedule(), 5, 10, TimeUnit.SECONDS);
	}
	
	private static class ClearSchedule implements Runnable {

		@Override
		public void run() {
			CacheManager.clearExpire();
		}
		
	}

}
