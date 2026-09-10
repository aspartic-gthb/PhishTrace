"use client";

import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis } from "recharts";

interface TrendChartProps {
  data?: Array<{
    date: string;
    count: number;
  }>;
}

export function TrendChart({ data }: TrendChartProps) {
  const chartData = data || [];

  return (
    <div className="p-6 rounded-2xl border border-slate-200 bg-white shadow-sm h-full flex flex-col">
      <div className="mb-6">
        <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider">
          Activity Trend
        </h3>
        <p className="text-xs text-slate-500 mt-1 font-medium">
          Threats and scans analyzed across active sessions
        </p>
      </div>

      <div className="h-[250px] w-full mt-auto">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={chartData}>
            <XAxis 
              dataKey="date" 
              stroke="#64748b" 
              fontSize={11} 
              tickLine={false} 
              axisLine={{ stroke: '#e2e8f0' }} 
              dy={10}
            />
            <Tooltip 
              cursor={{ stroke: '#cbd5e1' }}
              contentStyle={{ 
                backgroundColor: '#ffffff', 
                borderRadius: '8px',
                border: '1px solid #e2e8f0',
                boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
                color: '#0f172a',
                fontSize: '12px',
                fontWeight: 600
              }}
            />
            <Line 
              type="monotone" 
              dataKey="count" 
              name="Scans"
              stroke="#0f172a" 
              strokeWidth={2.5} 
              dot={{ r: 4, fill: "#0f172a", strokeWidth: 2, stroke: "#ffffff" }} 
              activeDot={{ r: 6, fill: "#0f172a" }} 
              isAnimationActive={true}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
