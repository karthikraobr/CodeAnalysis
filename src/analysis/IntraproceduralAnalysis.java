package analysis;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import reporting.Reporter;
import soot.Body;
import soot.Local;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.SpecialInvokeExpr;
import soot.jimple.Stmt;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.scalar.ForwardFlowAnalysis;

/**
 * Class implementing dataflow analysis
 */
public class IntraproceduralAnalysis extends ForwardFlowAnalysis<Unit, Set<FlowAbstraction>> {

	private final Logger logger = LoggerFactory.getLogger(getClass());

	public int flowThroughCount = 0;
	private final SootMethod method;
	private final Reporter reporter;

	public IntraproceduralAnalysis(Body b, Reporter reporter, int exercisenumber) {
		super(new ExceptionalUnitGraph(b));
		this.method = b.getMethod();
		this.reporter = reporter;

		logger.info("Analyzing method " + b.getMethod().getSignature() + "\n" + b);
	}

	@Override
	protected void flowThrough(Set<FlowAbstraction> taintsIn, Unit d, Set<FlowAbstraction> taintsOut) {
		Stmt s = (Stmt) d;
		//logger.info("Unit " + d);

		/*if(s.containsFieldRef())
		{
			System.out.println("Field Ref");
		}*/

		List<ValueBox> defBoxes = s.getDefBoxes();
		List<ValueBox> useBoxes = s.getUseBoxes();
		
		

		if(!(defBoxes.isEmpty() && taintsIn.isEmpty())){
			defBoxes.get(0).getValue();
				for(FlowAbstraction in : taintsIn)
				if(in.getLocal().equals(useBoxes.get(0).getValue())){
					System.out.println(defBoxes.get(0).getValue() + "\t is tainted tooo!!!!");
				}
			}
		
		if(!defBoxes.isEmpty()){
		for(ValueBox box: useBoxes)
		{
			Value value = box.getValue();
			if(value instanceof SpecialInvokeExpr && value.toString().contains("getSecret"))
			{
				//flag = true;
				System.out.println("Tainted\t"+defBoxes.get(0).getValue());
				taintsOut.add(new FlowAbstraction(s, (Local) defBoxes.get(0).getValue()));
				
			}
		}
		}
		
		
//		if(this.checkForTaint(s))
//		{
//			if(!s.getDefBoxes().isEmpty())
//			{
//				Value taintVariable = this.getTaintVariable(s);
//				System.out.println("taintVariable " + taintVariable);
//				if(taintVariable instanceof soot.jimple.internal.JimpleLocal /*&& !s.containsFieldRef()*/)
//				{
//					/*System.out.println("Local variable taint " + taintVariable);
//					FlowAbstraction taintflow = new FlowAbstraction(d, (Local) taintVariable);
//					taintsOut.add(taintflow);*/
//					reporter.report(this.method, d, d);
//				}
//				if(s.containsFieldRef())
//				{
//					System.out.println("taint Field Variable " + taintVariable);
//					reporter.report(this.method, d, d);
//				}
//				else
//					System.out.println("no taint");
//			}
//		}
		/* IMPLEMENT YOUR ANALYSIS HERE */


		// reporter.report(this.method, fa.getSource(), d);
	}

	@Override
	protected Set<FlowAbstraction> newInitialFlow() {
		return new HashSet<FlowAbstraction>();
	}

	@Override
	protected Set<FlowAbstraction> entryInitialFlow() {
		return new HashSet<FlowAbstraction>();
	}

	@Override
	protected void merge(Set<FlowAbstraction> in1, Set<FlowAbstraction> in2, Set<FlowAbstraction> out) {
		out.addAll(in1);
		out.addAll(in2);
	}

	@Override
	protected void copy(Set<FlowAbstraction> source, Set<FlowAbstraction> dest) {
		dest.clear();
		dest.addAll(source);
	}

	public void doAnalyis() {
		super.doAnalysis();
	}

	private Value getTaintVariable(Stmt s) 
	{
		Value taintVariable = null;
		for(ValueBox taintedvar:s.getDefBoxes())
		{
			taintVariable = taintedvar.getValue();
			//System.out.println("taint " + taintVariable);
			//System.out.println("s " + s);
		}
		return taintVariable;
	}

	private Boolean checkForTaint(Stmt s)
	{
		Boolean flag = false;
		for(ValueBox box: s.getUseBoxes())
		{
			Value currValue = box.getValue();
			if(currValue instanceof SpecialInvokeExpr && ((SpecialInvokeExpr) currValue).getMethod().getName().contains("Secret"))
			{
				flag = true;
			}
		}
		return flag;
	}

}
