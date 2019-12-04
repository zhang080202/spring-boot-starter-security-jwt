package com.github.security.schedule;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.github.security.utils.CacheManager;

/**
 * 清理黑名单中过期token 10秒执行一次
 * 
 * @author zhangyf
 *
 */
public class ClearBlacklistSchedule {

	private int clearInterval;

	public void initSchedule() {
		clearBlacklist();
	}

	public void clearBlacklist() {
		ScheduledExecutorService schedule = Executors.newScheduledThreadPool(2);
		schedule.scheduleAtFixedRate(new ClearSchedule(), 5, clearInterval/1000, TimeUnit.SECONDS);
	}

	public int getClearInterval() {
		return clearInterval;
	}

	public void setClearInterval(int clearInterval) {
		this.clearInterval = clearInterval;
	}

	private static class ClearSchedule implements Runnable {

		@Override
		public void run() {
			CacheManager.clearExpire();
		}

	}

}
