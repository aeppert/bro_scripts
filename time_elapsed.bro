export {
  type timeSpan: record {
    hours: int;
    minutes: int;
    seconds: int;
  };
}

function calc_elapsed_time(t1: time, t2: time) : timeSpan
{
  local ret: timeSpan;
  local timeInterval = double_to_count(time_to_double(t2) - time_to_double(t1));
  
  ret$hours   = (timeInterval / 3600);
  ret$minutes = (timeInterval - (ret$hours * 3600)) / 60;
  ret$seconds = (timeInterval % 60);
  
  return ret;
}
