package com.encore.playground.domain.feed.repository;

import com.encore.playground.domain.feed.entity.Feed;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

/**
 * 피드 글을 저장하는 리포지토리
 */
public interface FeedRepository extends JpaRepository<Feed, Long> {

//    List<Feed> findAllBy(Pageable pageable);
}