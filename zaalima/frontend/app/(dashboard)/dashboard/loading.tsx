export default function Loading() {
  return (
    <div className="space-y-6 animate-pulse">
      <div className="h-14 bg-[#111B2E] border border-[#263449] rounded-xl w-full" />
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3.5">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="h-24 bg-[#111B2E] border border-[#263449] rounded-xl" />
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 h-72 bg-[#111B2E] border border-[#263449] rounded-xl" />
        <div className="h-72 bg-[#111B2E] border border-[#263449] rounded-xl" />
      </div>
    </div>
  );
}
