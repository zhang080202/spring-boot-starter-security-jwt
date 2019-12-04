package com.github.security.utils;

import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 缓存管理器
 */
@SuppressWarnings("rawtypes")
public class CacheManager {
	
	private static Logger logger = LoggerFactory.getLogger(CacheManager.class);

	private static Map<String, CacheData> CACHE_DATA = new ConcurrentHashMap<String, CacheData>();

    public static final Integer ALWAYS_ACTIVE = 0;

    public static <T> T getData(String key) {
		CacheData<T> data = CACHE_DATA.get(key);
        if (data != null && (data.getExpire() <= ALWAYS_ACTIVE || data.getSaveTime() >= System.currentTimeMillis())) {
            return data.getData();
        }
        return null;
    }

    public static <T> void setData(String key, T data, int expire) {
        CACHE_DATA.put(key, new CacheData(data, expire));
    }

    public static void clear(String key) {
        CACHE_DATA.remove(key);
    }

    public static void clearAll() {
        CACHE_DATA.clear();
    }
    
    /**
     * @author zhangyf
     * 新增加删除已过期的对象
     */
    public static void clearExpire() {
    	logger.info("clear token cache starting, current cache size is {}", CACHE_DATA.size());
    	Iterator<Entry<String, CacheData>> iterator = CACHE_DATA.entrySet().iterator();
    	while (iterator.hasNext()) {
    		Entry<String, CacheData> entry = iterator.next();
			CacheData cache = entry.getValue();
			if (System.currentTimeMillis() - cache.getSaveTime() >= 0) {
				iterator.remove();
				logger.info("clear token {}", entry.getKey());
			}
		}
    	logger.info("clear token cache started, current cache size is {}", CACHE_DATA.size());
    }

    /**
     * 缓存当中存入的数据bean
     *
     * @param <T> 数据类型
     */
    private static class CacheData<T> {
        CacheData(T t, int expire) {
            this.data = t;
            this.expire = expire <= 0 ? 0 : expire;
            this.saveTime = System.currentTimeMillis() + this.expire;
        }

        /**
         * 缓存当中存入的数据
         */
        private T data;
        /**
         * 缓存中数据存活时间
         */
        private long saveTime;
        /**
         * 过期时间，默认可以调用ALWAYS_ACTIVE=0使数据一致保持活跃。<br>
         * <= 0标志一直活跃。
         */
        private long expire;

        public T getData() {
            return data;
        }

        public long getSaveTime() {
            return saveTime;
        }

        public long getExpire() {
            return expire;
        }
    }
}
