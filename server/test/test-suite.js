/**
 * BLITZ Cyber Threats & IOC Investigation Lab - Complete Verification Test Suite
 */

import { app } from '../app.js';
import { db, initDatabase } from '../db/database.js';
import { seedSyntheticEvents } from '../db/seed-data.js';

async function runTests() {
  console.log('====================================================');
  console.log('   RUNNING BLITZ LAB COMPREHENSIVE TEST SUITE       ');
  console.log('====================================================');

  initDatabase();
  seedSyntheticEvents();

  let passed = 0;
  let failed = 0;

  function assert(condition, testName) {
    if (condition) {
      console.log(`[PASS] ${testName}`);
      passed++;
    } else {
      console.error(`[FAIL] ${testName}`);
      failed++;
    }
  }

  // Start temporary HTTP server to probe via fetch
  const server = app.listen(3099, '127.0.0.1');

  try {
    const baseUrl = 'http://127.0.0.1:3099';

    // 1. Session creation and IP detection
    console.log('\n--- 1. Testing Session & Connection Info ---');
    let cookie = '';
    const res1 = await fetch(`${baseUrl}/api/session/me`);
    const setCookie = res1.headers.get('set-cookie');
    if (setCookie) {
      cookie = setCookie.split(';')[0];
    }
    const data1 = await res1.json();
    assert(res1.status === 200, 'Session endpoint returns HTTP 200');
    assert(data1.sessionId && data1.sessionId.startsWith('sess_'), 'Session ID automatically provisioned');
    assert(data1.publicIp && data1.publicIp !== 'IP ADDRESS: UNAVAILABLE', `Client IP detected: ${data1.publicIp}`);
    assert(data1.connectionStatus === 'ONLINE', 'Connection status is ONLINE');
    assert(data1.challenges.total === 3, 'Total challenges equals 3');

    // 2. Synthetic baseline logs verification
    console.log('\n--- 2. Testing Synthetic Baseline Events (500+ Requirement) ---');
    const resEvents = await fetch(`${baseUrl}/api/events?limit=5`, { headers: { cookie } });
    const eventsData = await resEvents.json();
    assert(eventsData.pagination.total >= 500, `Total events in DB >= 500 (Actual: ${eventsData.pagination.total})`);
    assert(eventsData.events.length === 5, 'Pagination limit returns 5 events');
    assert(eventsData.events[0].is_simulated === 1, 'Baseline event correctly labeled is_simulated = 1');

    // 3. Challenge 1: SQL Injection
    console.log('\n--- 3. Testing Challenge 1: SQL Injection ---');
    const resSqli = await fetch(`${baseUrl}/api/challenge/sqli/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', cookie },
      body: JSON.stringify({ username: "admin' --", password: "arbitrary_password" })
    });
    const sqliData = await resSqli.json();
    assert(resSqli.status === 200, 'SQLi login returns HTTP 200');
    assert(sqliData.success === true, 'SQLi authentication bypass succeeds');
    assert(sqliData.attackFlag === 'BLITZ{sql_auth_bypass_success}', 'SQLi Attack Flag is BLITZ{sql_auth_bypass_success}');
    assert(sqliData.account.username === 'admin', 'Dummy admin account returned');

    // Verify real event generated
    const resMyEvents = await fetch(`${baseUrl}/api/events?my_activity_only=true`, { headers: { cookie } });
    const myEvents = await resMyEvents.json();
    assert(myEvents.events.length >= 1, 'Actual student event created in database');
    const sqliEvt = myEvents.events.find(e => e.attack_category === 'sqli');
    assert(sqliEvt && sqliEvt.is_simulated === 0, 'SQLi event has is_simulated: 0');
    assert(sqliEvt && sqliEvt.source_ip === data1.publicIp, `Source IP in event matches detected IP (${sqliEvt?.source_ip})`);

    // Verify Investigation Flag revealed ONLY on details endpoint
    assert(sqliEvt.investigation_flag === undefined, 'Investigation flag is hidden in general event list');
    const resSqliDetail = await fetch(`${baseUrl}/api/events/${sqliEvt.id}`, { headers: { cookie } });
    const sqliDetail = await resSqliDetail.json();
    assert(sqliDetail.event.investigation_flag === 'BLITZ{sql_ioc_7f92kx}', 'Investigation Flag revealed on detail inspection: BLITZ{sql_ioc_7f92kx}');

    // 4. Challenge 2: Cross-Site Scripting (XSS)
    console.log('\n--- 4. Testing Challenge 2: Reflected XSS ---');
    const resXss = await fetch(`${baseUrl}/api/challenge/xss/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', cookie },
      body: JSON.stringify({ payload: "<script>alert('2')</script>" })
    });
    const xssData = await resXss.json();
    assert(resXss.status === 200, 'XSS verify returns HTTP 200');
    assert(xssData.attackFlag === 'BLITZ{xss_script_execution_success}', 'XSS Attack Flag is BLITZ{xss_script_execution_success}');

    // Verify XSS event and investigation flag
    const resMyEvents2 = await fetch(`${baseUrl}/api/events?my_activity_only=true`, { headers: { cookie } });
    const myEvents2 = await resMyEvents2.json();
    const xssEvt = myEvents2.events.find(e => e.attack_category === 'xss');
    assert(xssEvt && xssEvt.is_simulated === 0, 'XSS event recorded with is_simulated: 0');
    const resXssDetail = await fetch(`${baseUrl}/api/events/${xssEvt.id}`, { headers: { cookie } });
    const xssDetail = await resXssDetail.json();
    assert(xssDetail.event.investigation_flag === 'BLITZ{xss_ioc_4m82qp}', 'Investigation Flag revealed on detail inspection: BLITZ{xss_ioc_4m82qp}');

    // 5. Challenge 3: IDOR
    console.log('\n--- 5. Testing Challenge 3: IDOR ---');
    // Authorized profile 1001
    const resIdor1 = await fetch(`${baseUrl}/api/challenge/idor/profile/1001`, { headers: { cookie } });
    const idor1Data = await resIdor1.json();
    assert(idor1Data.profile.id === 1001, 'Authorized profile ID 1001 loaded');

    // Unauthorized target profile 1002
    const resIdor2 = await fetch(`${baseUrl}/api/challenge/idor/profile/1002`, { headers: { cookie } });
    const idor2Data = await resIdor2.json();
    assert(resIdor2.status === 200, 'IDOR profile 1002 returns HTTP 200');
    assert(idor2Data.profile.id === 1002 && idor2Data.profile.name === 'Jordan Smith', 'Target Jordan Smith profile exposed');
    assert(idor2Data.attackFlag === 'BLITZ{idor_unauthorized_access}', 'IDOR Attack Flag is BLITZ{idor_unauthorized_access}');

    // Verify IDOR event and investigation flag
    const resMyEvents3 = await fetch(`${baseUrl}/api/events?my_activity_only=true`, { headers: { cookie } });
    const myEvents3 = await resMyEvents3.json();
    const idorEvt = myEvents3.events.find(e => e.attack_category === 'idor');
    assert(idorEvt && idorEvt.severity === 'CRITICAL', 'IDOR event recorded with CRITICAL severity');
    const resIdorDetail = await fetch(`${baseUrl}/api/events/${idorEvt.id}`, { headers: { cookie } });
    const idorDetail = await resIdorDetail.json();
    assert(idorDetail.event.investigation_flag === 'BLITZ{idor_ioc_9p31mz}', 'Investigation Flag revealed on detail inspection: BLITZ{idor_ioc_9p31mz}');

    // 6. Flag Submission System
    console.log('\n--- 6. Testing Flag Validation & Progress Tracking ---');
    // Reject incorrect flag
    const resBadFlag = await fetch(`${baseUrl}/api/flags/submit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', cookie },
      body: JSON.stringify({ challenge_id: 'sqli', flag_type: 'attack', flag: 'BLITZ{wrong_flag}' })
    });
    const badFlagData = await resBadFlag.json();
    assert(badFlagData.isCorrect === false, 'Incorrect flag is rejected');

    // Submit correct flags
    const flagsToSubmit = [
      { cid: 'sqli', type: 'attack', flag: 'BLITZ{sql_auth_bypass_success}' },
      { cid: 'sqli', type: 'investigation', flag: 'BLITZ{sql_ioc_7f92kx}' },
      { cid: 'xss', type: 'attack', flag: 'BLITZ{xss_script_execution_success}' },
      { cid: 'xss', type: 'investigation', flag: 'BLITZ{xss_ioc_4m82qp}' },
      { cid: 'idor', type: 'attack', flag: 'BLITZ{idor_unauthorized_access}' },
      { cid: 'idor', type: 'investigation', flag: 'BLITZ{idor_ioc_9p31mz}' }
    ];

    for (const f of flagsToSubmit) {
      const resF = await fetch(`${baseUrl}/api/flags/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', cookie },
        body: JSON.stringify({ challenge_id: f.cid, flag_type: f.type, flag: f.flag })
      });
      const dataF = await resF.json();
      assert(dataF.isCorrect === true, `Flag accepted: ${f.cid} (${f.type})`);
    }

    // Verify 100% completion in progress
    const resProg = await fetch(`${baseUrl}/api/flags/progress`, { headers: { cookie } });
    const progData = await resProg.json();
    assert(progData.stats.completionPercentage === 100, 'Lab completion reaches 100%');
    assert(progData.stats.fullyCompletedChallenges === 3, 'All 3 challenges fully completed');
    assert(progData.stats.totalStagesCompleted === 6, 'All 6 stages validated');

    // 7. Session Isolation check
    console.log('\n--- 7. Testing Session Isolation ---');
    // Second student with different cookie
    const resStudent2 = await fetch(`${baseUrl}/api/session/me`);
    const student2Cookie = resStudent2.headers.get('set-cookie').split(';')[0];
    const dataStudent2 = await resStudent2.json();
    assert(dataStudent2.sessionId !== data1.sessionId, 'Second student receives distinct session ID');

    // Check student 2 cannot see student 1's real attack events
    const resStudent2Events = await fetch(`${baseUrl}/api/events?my_activity_only=true`, {
      headers: { cookie: student2Cookie }
    });
    const student2Events = await resStudent2Events.json();
    assert(student2Events.events.length === 0, 'Student 2 attack history is clean (cannot see Student 1 events)');

    console.log('\n====================================================');
    console.log(`   TEST RESULTS: ${passed} PASSED, ${failed} FAILED `);
    console.log('====================================================\n');
  } finally {
    server.close();
  }
}

runTests().catch(err => {
  console.error('Test suite failed:', err);
  process.exit(1);
});
