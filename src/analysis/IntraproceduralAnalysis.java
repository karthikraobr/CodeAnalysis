package analysis;

import java.util.HashSet;
import java.util.Set;

import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JInvokeStmt;
import soot.jimple.internal.JReturnStmt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reporting.Reporter;
import soot.Body;
import soot.Local;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
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
		Boolean retainTaint = false;

		if(s instanceof  JAssignStmt)
		{
			if(s.toString().contains("getSecret"))
			{
				if(!s.getDefBoxes().isEmpty()){
					for(ValueBox defBox:s.getDefBoxes()){
						taintsOut.add(getFlowAbstractionObj(s,defBox.getValue()));
						System.out.println("Intial Taint "+ defBox.getValue());
					}
				}
			}else{
				for(FlowAbstraction in : taintsIn){
					for(ValueBox useBox:s.getUseBoxes()){
						if(in.getLocal().equals(useBox.getValue())){
							for(ValueBox defBox:s.getDefBoxes()){
								taintsOut.add(getFlowAbstractionObj(s,defBox.getValue()));
								System.out.println(defBox.getValue() + " is tainted because of "+useBox.getValue());
							}

						}else{
							retainTaint = true;
							//taintsOut.addAll(taintsIn);
						}
					}

				}
				if(!taintsIn.isEmpty())
				{
					retainTaint = true;
					//taintsOut.addAll(taintsIn);
				}

			}
		}
		else if ((s instanceof JInvokeStmt && !s.toString().contains("getSecret")) || s instanceof JReturnStmt){
			for(FlowAbstraction in : taintsIn)
			{
				for(ValueBox useBox:s.getUseBoxes()){
					if(in.getLocal().equals(useBox.getValue())){
						System.out.println(useBox.getValue() + " is Leaking Out!");
						reporter.report(this.method, in.getSource(), d);
					}

					else{
						retainTaint = true;
						//taintsOut.addAll(taintsIn);
					}
				}

			}
		}
		if(retainTaint){
			taintsOut.addAll(taintsIn);
		}
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
	private FlowAbstraction getFlowAbstractionObj(Stmt s,Value value)
	{
		return new FlowAbstraction(s, (Local)value);
	}
}
