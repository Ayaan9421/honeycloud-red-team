import { useState, useEffect } from 'react';

/**
 * A custom hook to simulate real-time data updates.
 * In a real application, this would use WebSockets or Server-Sent Events.
 */
export function useRealTimeData<T>(initialData: T[], updateFrequency = 3000, generator: () => T) {
  const [data, setData] = useState<T[]>(initialData);

  useEffect(() => {
    const interval = setInterval(() => {
      const newItem = generator();
      setData(prev => [newItem, ...prev].slice(0, 50));
    }, updateFrequency);

    return () => clearInterval(interval);
  }, [updateFrequency, generator]);

  return data;
}

/**
 * Simulates a long-running process with progress updates.
 */
export function useAsyncProcess(duration = 5000) {
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState('Idle');
  const [isProcessing, setIsProcessing] = useState(false);

  const startProcess = (steps: string[]) => {
    setIsProcessing(true);
    let currentStep = 0;
    const interval = duration / steps.length;

    const runStep = () => {
      if (currentStep < steps.length) {
        setStatus(steps[currentStep]);
        setProgress(((currentStep + 1) / steps.length) * 100);
        currentStep++;
        setTimeout(runStep, interval);
      } else {
        setStatus('Completed');
        setIsProcessing(false);
      }
    };

    runStep();
  };

  return { progress, status, isProcessing, startProcess };
}
