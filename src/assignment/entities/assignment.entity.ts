import { Model } from "src/model/entities/model.entity";
import { Result } from "src/results/entities/result.entity";
import { User } from "src/users/entities/user.entity";
import { Column, CreateDateColumn, Entity, ManyToOne, OneToOne, PrimaryGeneratedColumn } from "typeorm";

@Entity()
export class Assignment {
    @PrimaryGeneratedColumn()
    id: number

    @ManyToOne(() => User, (user) => user.assignment)
    student: User

    @ManyToOne(() => Model, (model) => model.assigments)
    model: Model;

    @Column('text')
    content: string;

    @CreateDateColumn()
    submittedAt: Date

    @OneToOne(()=>Result,(result)=>result.assignment)
    result:Result
}
