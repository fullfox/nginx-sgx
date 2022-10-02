import http from 'k6/http';
import { check, group, sleep } from 'k6';

// PARAMETERS:
const BASE_URL = 'http://0.0.0.0:4000'; // Target

const duration = 10; //duration of each scenario, in second

const static_rps = 0; //If different from zero, override all scenarios and only run one scenario with the specified RPS

const rps_min  = 100;
const rps_step = 100;
const rps_max  = 500;

// END OF PARAMETERS


// Generate scenarios:
let scenarios_list = {};
if(static_rps != 0){
  scenarios_list["s0"] = {
    executor: 'constant-arrival-rate',
    rate: static_rps,
    duration: duration + 's',
    gracefulStop: '0s',
    preAllocatedVUs: static_rps,
    maxVUs: static_rps*2,
    tags: { duration: duration+'', rps: static_rps+''},
  };
} else {
  for (let index = 0; index <= (rps_max - rps_min)/rps_step; index++) {
    let rps = index * rps_step + rps_min;

    scenarios_list["s" + index] = {
      executor: 'constant-arrival-rate',
      rate: rps,
      duration: duration + 's',
      gracefulStop: '0s',
      preAllocatedVUs: rps,
      maxVUs: rps*2,
      startTime: (index*duration) + 's',
      tags: { duration: duration+'', rps: rps+''},
    };
  }
}

export const options = {
 scenarios: scenarios_list,
 noConnectionReuse: true,  // for batch mode
 noVUConnectionReuse: true // for batch mode too
};

export default function () {
  http.get(BASE_URL);
}
